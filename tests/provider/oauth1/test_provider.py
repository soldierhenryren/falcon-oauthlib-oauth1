import logging
import codecs
import falcon
import jinja2
import os
from urlparse import urlunsplit
from falcon.testing import DEFAULT_HOST
from oauthlib.oauth1 import Client, add_params_to_uri
from .create_clean_db_configure_pytest import app, Client_realms, Client_username, Client_realm_list
from .falcon_framework import application, oauth
from .create_clean_db_configure_pytest import Client_key, Client_secret, Client_redirects

try:
    from urlparse import urlparse, urlunparse, parse_qs
except ImportError:
    from urllib.parse import urlparse, urlunparse, parse_qs
log = logging.getLogger('falcon_oauth1_log')

app = app

Callback_url = Client_redirects.split()[0]


def test_simple_get(client):
    class MyResource:
        def on_get(self, req, resp):
            resp.body = '{"foo":"bar"}'

    application.add_route('/resource', MyResource())
    resp = client.get('/resource')
    assert resp.json['foo'] == 'bar'


def test_request_token(client):
    class RequestTokenHandler:
        @oauth.request_token_handler
        def on_post(self, req, resp):
            pass

    routepath = '/auth/request_token'
    application.add_route(routepath, RequestTokenHandler())
    test_client = Client(Client_key,
                         client_secret=Client_secret,
                         callback_uri=Callback_url,
                         realm=Client_realms)
    scheme, netloc, query, fragment = 'http', DEFAULT_HOST, '', ''
    full_url = urlunsplit((scheme, netloc, routepath, query, fragment))
    tu, th, tb = test_client.sign(full_url, http_method='POST')
    resp = client.post(tu, None, headers=th)
    assert resp.status == '200 OK'
    assert resp.headers['Content-Type'] == 'application/x-www-form-urlencoded'
    assert 'oauth_token_secret' in resp.body
    assert 'oauth_token' in resp.body
    assert 'oauth_callback_confirmed=true' in resp.body
    return resp, Client_key, Client_secret, Callback_url


def test_authorization_with_request_token(client):
    class AuthorizationHandler:
        @oauth.authorize_handler
        def on_get(self, req, resp):
            template = load_template('tests/provider/oauth1/templates/index.html')
            resp.body = template.render(client_key=request_token, realms=Client_realms, url=routepath)
            resp.status = falcon.HTTP_200
            resp.content_type = 'text/html'
            assert req.context['realms'] == Client_realms
            assert req.context['resource_owner_key'] == request_token

        @oauth.authorize_handler
        def on_post(self, req, resp):
            return req

    routepath = '/auth/authorize'
    application.add_route(routepath, AuthorizationHandler())

    resp_request_token, client_key, client_secret, callback_url = test_request_token(client)
    request_token = parse_qs(resp_request_token.body).get('oauth_token')[0]
    request_token_secret = parse_qs(resp_request_token.body).get('oauth_token_secret')[0]
    scheme, netloc, query, fragment = 'http', DEFAULT_HOST, '', ''
    original_url = urlunsplit((scheme, netloc, routepath, query, fragment))
    params = {'oauth_token': request_token, 'oauth_callback': callback_url}
    full_url = add_params_to_uri(original_url, params)
    resp = client.get(full_url)
    assert Client_realms in unicode(resp.body, 'utf-8')
    assert request_token in unicode(resp.body, 'utf-8')

    temp_path = os.path.abspath(os.path.join('tests/provider/oauth1/templates/grant_temp.html'))
    with codecs.open(os.path.abspath(temp_path), 'w+', encoding='utf8') as f:
        f.write(unicode(resp.body, 'utf-8'))
    scheme, url = 'file', temp_path
    temp_url = urlunsplit((scheme, None, url, None, None))
    # webbrowser.open(temp_url)
    data = [(u'username', Client_username),
            (u'password', u'not_wrong')]
    header = {u'Content-Type': u'application/x-www-form-urlencoded'}
    resp = client.post(full_url, data, headers=header)
    location = resp.headers['location']
    parts = urlparse(location)
    assert callback_url == urlunparse((parts.scheme, parts.netloc, parts.path, '', '', ''))
    assert parse_qs(parts.query).get('oauth_verifier') is not None
    assert parse_qs(parts.query).get('oauth_token') is not None
    return location, request_token_secret


def test_access_token_handler(client):
    class AccessTokenHandler:
        @oauth.access_token_handler
        def on_post(self, req, resp):
            pass

    routepath = '/auth/access_token'
    application.add_route(routepath, AccessTokenHandler())
    location, oauth_token_secret = test_authorization_with_request_token(client)
    oauth_token = parse_qs(urlparse(location).query).get('oauth_token')[0]
    oauth_token_verify = parse_qs(urlparse(location).query).get('oauth_verifier')[0]
    test_client = Client(Client_key,
                         client_secret=Client_secret,
                         resource_owner_key=oauth_token,
                         resource_owner_secret=oauth_token_secret,
                         verifier=oauth_token_verify)
    scheme, netloc, query, fragment = 'http', DEFAULT_HOST, '', ''
    full_url = urlunsplit((scheme, netloc, routepath, query, fragment))
    tu, th, tb = test_client.sign(full_url, http_method='POST')
    resp = client.post(tu, None, headers=th)
    assert resp.status == '200 OK'
    assert resp.headers['Content-Type'] == 'application/x-www-form-urlencoded'
    assert 'oauth_token_secret' in resp.body
    assert 'oauth_token' in resp.body
    return resp


def test_validate_protected_resource_request(client):
    class ValidateProtectedResourceRequestUsers:
        @oauth.protected_resource_handler(Client_realm_list[0])
        def on_post(self, req, resp):
            resp.content_type = 'application/x-www-form-urlencoded'
            resp.body = u'I can access users'

    class ValidateProtectedResourceRequestAddress:
        @oauth.protected_resource_handler(Client_realm_list[1])
        def on_post(self, req, resp):
            resp.content_type = 'application/x-www-form-urlencoded'
            resp.body = u'I can access address'

    resp_access_token = test_access_token_handler(client)
    access_token = parse_qs(resp_access_token.body).get('oauth_token')[0]
    access_token_secret = parse_qs(resp_access_token.body).get('oauth_token_secret')[0]

    test_client = Client(Client_key,
                         client_secret=Client_secret,
                         resource_owner_key=access_token,
                         resource_owner_secret=access_token_secret)

    routepath_user = '/users'
    application.add_route(routepath_user, ValidateProtectedResourceRequestUsers())
    scheme, netloc, query, fragment = 'http', DEFAULT_HOST, '', ''
    full_url = urlunsplit((scheme, netloc, routepath_user, query, fragment))
    tu, th, tb = test_client.sign(full_url, http_method='POST')
    resp = client.post(tu, None, headers=th)
    assert resp.status == '200 OK'
    assert resp.headers['content-type'] == 'application/x-www-form-urlencoded'
    assert resp.body == u'I can access users'

    routepath_address = '/address'
    application.add_route(routepath_address, ValidateProtectedResourceRequestAddress())
    scheme, netloc, query, fragment = 'http', DEFAULT_HOST, '', ''
    full_url = urlunsplit((scheme, netloc, routepath_address, query, fragment))
    tu, th, tb = test_client.sign(full_url, http_method='POST')
    resp = client.post(tu, None, headers=th)
    assert resp.status == '200 OK'
    assert resp.headers['content-type'] == 'application/x-www-form-urlencoded'
    assert resp.body == u'I can access address'


def load_template(name):
    path = os.path.join(name)
    with codecs.open(os.path.abspath(path), 'r', encoding='utf8') as fp:
        source = fp.read()
        return jinja2.Template(source)
