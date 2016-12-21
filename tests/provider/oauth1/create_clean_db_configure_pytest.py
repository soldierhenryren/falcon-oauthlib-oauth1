# coding: utf-8
import base64
import logging
import random
import string
from urlparse import urlparse
import sys
import pytest
from .falcon_framework import application, User, Client, config, Grant, Token

log = logging.getLogger('falcon_oauth1.test')
if sys.version_info[0] == 3:
    python_version = 3
    string_type = str
else:
    python_version = 2
    string_type = unicode


def generat_client_key(size=20, chars=string.letters):
    return ''.join(random.choice(chars) for _ in range(size))


def generat_client_secret(size=20, chars=string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def generat_client_name(size=10, chars=string.letters):
    return ''.join(random.choice(chars) for _ in range(size))


# for test
Client_username = generat_client_name()
Client_key = generat_client_key()
Client_secret = generat_client_secret()
Client_redirects = 'http://localhost/callback http://localhost:8000/callback'
Client_realms = ' '.join(config.get('OAUTH1_PROVIDER_REALMS', []))
Client_realm_list = config.get('OAUTH1_PROVIDER_REALMS', [])


def db_drop():
    Client.drop_table()
    User.drop_table()
    Grant.drop_table()


@pytest.fixture
def db_user_create():
    def _(**kwargs):
        kwargs.setdefault('username', Client_username)
        return User.create(**kwargs)

    result = _()
    if result:
        log.debug(str(result) + ' record created ' + result.username)


@pytest.fixture
def db_client_create():
    def _(**kwargs):
        defaults = dict(client_key=Client_key, client_secret=Client_secret,
                        _redirect_uris=Client_redirects)
        defaults.update(kwargs)
        return Client.create(**defaults)

    result = _()
    if result:
        log.debug(str(result) + ' record created ' + result.client_key + '/' + result.client_secret)


# create
def db_create():
    Client.create_table(True)
    User.create_table(True)
    Grant.create_table(True)
    Token.create_table(True)


@pytest.fixture
def app():
    db_create()
    db_client_create()
    db_user_create()
    yield application
    db_drop()


def to_unicode(text):
    if not isinstance(text, string_type):
        text = text.decode('utf-8')
    return text


def to_bytes(text):
    if isinstance(text, string_type):
        text = text.encode('utf-8')
    return text


def to_base64(text):
    return to_unicode(base64.b64encode(to_bytes(text)))


def clean_url(location):
    location = to_unicode(location)
    ret = urlparse(location)
    return '%s?%s' % (ret.path, ret.query)
