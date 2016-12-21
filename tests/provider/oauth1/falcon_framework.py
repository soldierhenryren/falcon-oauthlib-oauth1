# coding: utf-8
import logging
from functools import wraps
import falcon
from peewee import *
from dateutil import parser
from falcon_oauth1.provider.oauth1 import OAuthProvider

log = logging.getLogger('falcon_oauth1.test')
db = SqliteDatabase(':memory:')
config = {
    'OAUTH1_PROVIDER_ENFORCE_SSL': False,
    'OAUTH1_PROVIDER_KEY_LENGTH': (3, 30),
    'OAUTH1_PROVIDER_REALMS': ['users', 'address'],
}

oauth = OAuthProvider(config=config)


class DateTimeField(DateTimeField):
    def python_value(self, value):
        if value:
            return parser.parse(value)
        return value


# models
class BaseModel(Model):
    class Meta:
        database = db


class User(BaseModel):
    username = CharField(max_length=40, unique=True, index=True)

    def check_password(self, password):
        return password != 'wrong'


class Client(BaseModel):
    client_key = CharField(primary_key=True, max_length=40)
    client_secret = CharField(max_length=55, unique=True, index=True)
    rsa_key = CharField(max_length=55, null=True)
    _realms = TextField(null=True)
    _redirect_uris = TextField(null=True)

    @property
    def user(self):
        return User.query.get(1)

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return str(self._redirect_uris).split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @property
    def default_realms(self):
        if self._realms:
            return str(self._realms).split()
        return []


class Grant(BaseModel):
    user_id = ForeignKeyField(User, related_name='users', on_delete='CASCADE', null=True)
    client_key = CharField(null=True)
    token = CharField(unique=True, index=True)
    secret = CharField()
    verifier = CharField(null=True)
    expires = DateTimeField(null=True)
    redirect_uri = TextField()
    _realms = TextField(null=True)

    def delete(self):
        self.delete_instance()
        return self

    @property
    def realms(self):
        if self._realms:
            return str(self._realms).split()
        return []


class Token(BaseModel):
    client_key = ForeignKeyField(Client, null=False)
    user_id = ForeignKeyField(User)
    token = CharField()
    secret = CharField()
    _realms = TextField()

    @property
    def realms(self):
        if self._realms:
            return str(self._realms).split()
        return []


def attach_user(func):
    def attach(kwargs):
        kwargs['headers']['X-User-Id'] = str(User.get().id)

    @wraps(func)
    def inner(*args, **kwargs):
        # Subtly plug in authenticated user.
        if 'client' in kwargs:
            kwargs['client'] = kwargs['client'](before=attach)
        return func(*args, **kwargs)

    return inner


@oauth.clientgetter
def query_client(client_key):
    return Client.select().where(Client.client_key == client_key).first()


@oauth.tokengetter
def query_access_token(client_key, token):
    t = Token.get(Token.client_key == client_key, Token.token == token)
    return t


@oauth.tokensetter
def create_access_token(token, request):
    Token.create(
        client_key=request.client_key,
        user_id=request.user_id,
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        _realms=token['oauth_authorized_realms']
    )


@oauth.grantgetter
def query_request_token(token):
    return Grant.get(Grant.token == token)


@oauth.grantsetter
def create_grant(token, request):
    realmstr = None
    if request.realms:
        realmstr = ' '.join(request.realms)
    # todo Add expiretime
    grant = Grant.create(
        token=token['oauth_token'],
        secret=token['oauth_token_secret'],
        client_key=request.oauth_params['oauth_consumer_key'],
        redirect_uri=request.oauth_params['oauth_callback'],
        _realms=realmstr)
    return grant


@oauth.verifiergetter
def query_verifier(verifier, token):
    return Grant.get(Grant.verifier == verifier, Grant.token == token)


@oauth.verifiersetter
def create_verifier(token, verifier, request):
    q = Grant.update(verifier=verifier[u'oauth_verifier'], user_id=verifier[u'user_id']).where(Grant.token == token)
    return q.execute()


@oauth.noncegetter
def query_nonce(**kwargs):
    return None


@oauth.noncesetter
def create_nonce(**kwargs):
    return None


@oauth.authenticateuser
def authenticate_user(username, password):
    user = User.get(User.username == username)
    if user.check_password(password=password):
        return user.id
    return None


models = [Client, User, Token, Grant]
application = falcon.API()
application.req_options.auto_parse_form_urlencoded = True
