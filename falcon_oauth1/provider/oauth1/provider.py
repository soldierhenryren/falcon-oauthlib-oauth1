# coding: utf-8

import logging
from functools import wraps
import falcon
from oauthlib.common import add_params_to_uri, urlencode
from oauthlib.oauth1 import WebApplicationServer
from oauthlib.oauth1.rfc5849 import errors
from falcon_oauth1.utils import extract_params, patch_response
from validator import OAuthRequestValidator

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT, level=logging.WARN)
log = logging.getLogger('falcon_oauth1')


class OAuthProvider(object):
    def __init__(self, error_uri=None, expires_in=None,
                 usergetter=None, clientgetter=None, tokengetter=None,
                 tokensetter=None, grantgetter=None, grantsetter=None,
                 token_generator=None, refresh_token_generator=None,
                 authenticateuser=None, server=None, on_error=None, config=None):
        self._error_uri = error_uri
        self._expires_in = expires_in
        self._usergetter = usergetter
        self._clientgetter = clientgetter
        self._tokengetter = tokengetter
        self._tokensetter = tokensetter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter
        self._authenticateuser = authenticateuser
        self._token_generator = token_generator
        self._refresh_token_generator = refresh_token_generator
        self._server = server
        self._on_error = on_error
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._config = config

    @property
    def error_uri(self):
        if not self._error_uri:
            self._error_uri = '/oauth/error'
        return self._error_uri

    @property
    def server(self):
        if hasattr(self, '_validator'):
            return WebApplicationServer(self._validator)
        if hasattr(self, '_clientgetter') and \
                hasattr(self, '_tokengetter') and \
                hasattr(self, '_tokensetter') and \
                hasattr(self, '_noncegetter') and \
                hasattr(self, '_noncesetter') and \
                hasattr(self, '_grantgetter') and \
                hasattr(self, '_grantsetter') and \
                hasattr(self, '_verifiergetter') and \
                hasattr(self, '_verifiersetter') and \
                hasattr(self, '_authenticateuser'):
            validator = OAuthRequestValidator(
                clientgetter=self._clientgetter,
                tokengetter=self._tokengetter,
                grantgetter=self._grantgetter,
                noncegetter=self._noncegetter,
                noncesetter=self._noncesetter,
                tokensetter=self._tokensetter,
                grantsetter=self._grantsetter,
                verifiergetter=self._verifiergetter,
                verifiersetter=self._verifiersetter,
                authenticateuser=self._authenticateuser,
                config=self._config)
            self._validator = validator
            server = WebApplicationServer(validator)
            return server
        raise RuntimeError(
            'application not bound to required getters and setters'
        )

    def before_request(self, f):
        self._before_request_funcs.append(f)
        return f

    def after_request(self, f):
        self._after_request_funcs.append(f)
        return f

    def clientgetter(self, f):
        self._clientgetter = f
        return f

    def tokengetter(self, f):
        self._tokengetter = f
        return f

    def tokensetter(self, f):
        self._tokensetter = f
        return f

    def grantgetter(self, f):
        self._grantgetter = f
        return f

    def grantsetter(self, f):
        self._grantsetter = f
        return f

    def noncegetter(self, f):
        self._noncegetter = f
        return f

    def noncesetter(self, f):
        self._noncesetter = f
        return f

    def verifiergetter(self, f):
        self._verifiergetter = f
        return f

    def verifiersetter(self, f):
        self._verifiersetter = f
        return f

    def authenticateuser(self, f):
        self._authenticateuser = f
        return f

    def request_token_handler(self, f):
        @wraps(f)
        def decorated(handler, req, resp):
            server = self.server
            uri, http_method, body, headers = extract_params(req)
            credentials = f(handler, req, resp)
            try:
                headers, body, status = server.create_request_token_response(uri, http_method, body, headers,
                                                                             credentials)
            except errors.OAuth1Error as e:
                return _error_response(e, resp)
            else:
                return patch_response(resp, headers, body, status)

        return decorated

    def authorize_handler(self, f):
        @wraps(f)
        def decorated(handler, req, resp):
            if req.method == 'POST':
                if not f(handler, req, resp):
                    uri = add_params_to_uri(
                        self.error_uri, [('error', 'denied')]
                    )
                    resp.status = falcon.HTTP_SEE_OTHER
                    # todo need check how redirect in falcon
                    raise falcon.HTTPMovedPermanently(uri)
                    # return decorated

                return self.confirm_authorization_request(req, resp)
            server = self.server
            uri, http_method, body, headers = extract_params(req)
            redirect_uri = req.params.get('oauth_callback', self.error_uri)
            log.debug('Found redirect_uri %s.', redirect_uri)
            try:
                realms, credentials = server.get_realms_and_credentials(
                    uri, http_method=http_method, body=body, headers=headers
                )
                req.context['realms'] = ' '.join(realms)
                req.context.update(credentials)
                return f(handler, req, resp)
            except errors.OAuth1Error as e:
                log.debug('OAuth1Error: %r', e)
                resp.status = falcon.HTTP_SEE_OTHER
                resp.headers['Location'] = redirect_uri

        return decorated

    def confirm_authorization_request(self, req, resp):
        """When consumer confirm the authrozation."""
        server = self.server
        uri, http_method, body, headers = extract_params(req)
        redirect_uri = req.params.get('oauth_callback', self.error_uri)
        username = req.params.get('username', None)
        password = req.params.get('password', None)
        realms = req.params.get('realms', None)

        log.debug('Found oauth_callback %s.', redirect_uri)
        try:
            user_id = self._authenticateuser(username, password)
            if not user_id:
                raise errors.OAuth1Error
            credentials = req.params.get('credentials', {u'user_id': user_id})
            # realms, credentials = server.get_realms_and_credentials(
            #     uri, http_method=http_method, body=body, headers=headers
            # )
            headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, realms, credentials
            )

        except errors.OAuth1Error as e:
            log.debug('OAuth1Error: %r', e)
            resp.status = falcon.HTTP_SEE_OTHER
            raise falcon.HTTPMovedPermanently(redirect_uri)
        else:
            log.debug('Authorization successful.')
            return patch_response(resp, headers, body, status)

    def access_token_handler(self, f):
        @wraps(f)
        def decorated(handler, req, resp):
            server = self.server
            uri, http_method, body, headers = extract_params(req)
            credentials = f(handler, req, resp)
            try:
                headers, token, status = server.create_access_token_response(
                    uri, http_method, body, headers, credentials)
            except errors.OAuth1Error as e:
                return _error_response(e, resp)
            else:
                return patch_response(resp, headers, token, status)

        return decorated

    def protected_resource_handler(self, *realms):
        """Protected resource access token check"""

        def wrapper(f):
            @wraps(f)
            def decorated(handler, req, resp):
                for func in self._before_request_funcs:
                    func()
                if hasattr(req, 'oauth') and req.oauth:
                    return f(handler, req, resp)
                server = self.server
                uri, http_method, body, headers = extract_params(req)
                try:
                    valid, oauth_req = server.validate_protected_resource_request(
                        uri, http_method, body, headers, realms
                    )
                except Exception as e:
                    log.warn('Exception: %r', e)
                    e.urlencoded = urlencode([('error', 'unknown')])
                    e.status_code = 400
                    return _error_response(e, resp)
                for func in self._after_request_funcs:
                    valid, oauth_req = func(valid, oauth_req)

                if not valid:
                    if not valid:
                        raise falcon.HTTPMovedPermanently('/sign_in')

                    # alias user for convenience
                    req.context['oauth'] = oauth_req
                    return f(handler, req, resp)

            return decorated

        return wrapper


def _error_response(e, resp):
    log.debug('OAuth1Error: %r', e)
    resp.status = falcon.HTTP_SEE_OTHER
    resp.headers['Content-Type'] = 'application/x-www-form-urlencoded'
