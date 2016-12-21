# -*- coding: utf-8 -*-
import logging

import requests
from oauthlib.common import extract_params, add_params_to_uri, urldecode as _urldecode
from oauthlib.oauth1 import Client, SIGNATURE_RSA, SIGNATURE_HMAC, SIGNATURE_TYPE_AUTH_HEADER, SIGNATURE_TYPE_BODY
from requests.auth import AuthBase
from requests.compat import is_py3
from requests.utils import to_native_string

try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded'
CONTENT_TYPE_MULTI_PART = 'multipart/form-data'
if is_py3:
    unicode = str
log = logging.getLogger('falcon_oauth1_oauth1')


def urldecode(body):
    """Parse query or json to python dictionary"""
    try:
        return _urldecode(body)
    except:
        import json
        return json.loads(body)


class VerifierMissing(ValueError):
    pass


class TokenMissing(ValueError):
    def __init__(self, message, response):
        super(TokenMissing, self).__init__(message)
        self.response = response


class TokenRequestDenied(ValueError):
    def __init__(self, message, response):
        super(TokenRequestDenied, self).__init__(message)
        self.response = response

    @property
    def status_code(self):
        """For backwards-compatibility purposes"""
        return self.response.status_code


class OAuth1(AuthBase):
    client_class = Client

    def __init__(self,
                 client_key,
                 client_secret=None,
                 resource_owner_key=None,
                 resource_owner_secret=None,
                 callback_uri=None,
                 signature_method=SIGNATURE_HMAC,
                 signature_type=SIGNATURE_TYPE_AUTH_HEADER,
                 rsa_key=None,
                 verifier=None,
                 decoding='utf-8',
                 client_class=None,
                 force_include_body=False,
                 **kwargs):
        try:
            signature_type = signature_type.upper()
        except ArithmeticError:
            pass
        client_class = client_class or self.client_class

        self.force_include_body = force_include_body

        self.client = client_class(client_key, client_secret, resource_owner_key,
                                   resource_owner_secret, callback_uri, signature_method,
                                   signature_type, rsa_key, verifier, decoding=decoding, **kwargs)

    def __call__(self, r):
        log.debug('Signing request %s using client %s', r, self.client)
        content_type = r.headers.get('Content-Type', '')
        if (not content_type and extract_params(r.body) or self.client.signature_type == SIGNATURE_TYPE_BODY):
            content_type = CONTENT_TYPE_FORM_URLENCODED
        if not isinstance(content_type, unicode):
            content_type = content_type.decode('utf-8')

        is_form_encoded = (CONTENT_TYPE_FORM_URLENCODED in content_type)

        log.debug('Including body in call to sign: %s',
                  is_form_encoded or self.force_include_body)
        if is_form_encoded:
            r.headers['Content-Type'] = CONTENT_TYPE_FORM_URLENCODED
            r.url, headers, r.body = self.client.sign(
                unicode(r.url), unicode(r.method), r.body or '', r.headers)
        elif self.force_include_body:
            r.url, headers, r.body = self.client.sign(
                unicode(r.url), unicode(r.method), r.body or '', r.headers)
        else:
            r.url, headers, _ = self.client.sign(
                unicode(r.url), unicode(r.method), None, r.headers)
        r.prepare_headers(headers)
        r.url = to_native_string(r.url)
        log.debug('Updated url: %s', r.url)
        log.debug('Updated headers: %s', headers)
        log.debug('Updated body: %r', r.body)
        return r


class OAuth1Session(requests.Session):
    def __init__(self, client_key,
                 client_secret=None,
                 resource_owner_key=None,
                 resource_owner_secret=None,
                 callback_uri=None,
                 signature_method=SIGNATURE_HMAC,
                 signature_type=SIGNATURE_TYPE_AUTH_HEADER,
                 rsa_key=None,
                 verifier=None,
                 client_class=None,
                 force_include_body=False,
                 **kwargs):
        super(OAuth1Session, self).__init__()
        self._client = OAuth1(client_key,
                              client_secret=client_secret,
                              resource_owner_key=resource_owner_key,
                              resource_owner_secret=resource_owner_secret,
                              callback_uri=callback_uri,
                              signature_method=signature_method,
                              signature_type=signature_type,
                              rsa_key=rsa_key,
                              verifier=verifier,
                              client_class=client_class,
                              force_include_body=force_include_body,
                              **kwargs)
        self.auth = self._client

    @property
    def authorized(self):
        if self._client.client.signature_method == SIGNATURE_RSA:
            return bool(self._client.client.resource_owner_key)
        else:
            return (
                bool(self._client.client.client_secret) and
                bool(self._client.client.resource_owner_key) and
                bool(self._client.client.resource_owner_secret)
            )

    def authorization_url(self, url, request_token=None, **kwargs):
        kwargs['oauth_token'] = request_token or self._client.client.resource_owner_key
        log.debug('Adding parameters %s to url %s', kwargs, url)
        return add_params_to_uri(url, kwargs.items())

    def fetch_request_token(self, url, realm=None, **request_kwargs):
        self._client.client.realm = ' '.join(realm) if realm else None
        token = self._fetch_token(url, **request_kwargs)
        log.debug('Resetting callback_uri and realm (not needed in next phase).')
        self._client.client.callback_uri = None
        self._client.client.realm = None
        return token

    def fetch_access_token(self, url, verifier=None, **request_kwargs):
        if verifier:
            self._client.client.verifier = verifier
        if not getattr(self._client.client, 'verifier', None):
            raise VerifierMissing('No client verifier has been set.')
        token = self._fetch_token(url, **request_kwargs)
        log.debug('Resetting verifier attribute, should not be used anymore.')
        self._client.client.verifier = None
        return token

    def parse_authorization_response(self, url):
        log.debug('Parsing token from query part of url %s', url)
        token = dict(urldecode(urlparse(url).query))
        log.debug('Updating internal client token attribute.')
        self._populate_attributes(token)
        return token

    def _populate_attributes(self, token):
        if 'oauth_token' in token:
            self._client.client.resource_owner_key = token['oauth_token']
        else:
            raise TokenMissing(
                'Response does not contain a token: {resp}'.format(resp=token),
                token,
            )
        if 'oauth_token_secret' in token:
            self._client.client.resource_owner_secret = (
                token['oauth_token_secret'])
        if 'oauth_verifier' in token:
            self._client.client.verifier = token['oauth_verifier']

    def _fetch_token(self, url, **request_kwargs):
        log.debug('Fetching token from %s using client %s', url, self._client.client)
        r = self.post(url, **request_kwargs)

        if r.status_code >= 400:
            error = "Token request failed with code %s, response was '%s'."
            raise TokenRequestDenied(error % (r.status_code, r.text), r)

        log.debug('Decoding token from response "%s"', r.text)
        try:
            token = dict(urldecode(r.text.strip()))
        except ValueError as e:
            error = ("Unable to decode token from token response. "
                     "This is commonly caused by an unsuccessful request where"
                     " a non urlencoded error message is returned. "
                     "The decoding error was %s""" % e)
            raise ValueError(error)

        log.debug('Obtained token %s', token)
        log.debug('Updating internal client attributes from token data.')
        self._populate_attributes(token)
        return token

    def rebuild_auth(self, prepared_request, response):
        if 'Authorization' in prepared_request.headers:
            # If we get redirected to a new host, we should strip out
            # any authentication headers.
            prepared_request.headers.pop('Authorization', True)
            prepared_request.prepare_auth(self.auth)
        return
