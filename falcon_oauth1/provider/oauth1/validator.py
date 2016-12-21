# coding=utf-8
import logging
from oauthlib.common import to_unicode
from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1.rfc5849 import SIGNATURE_METHODS

log = logging.getLogger('falcon_oauth1')


class OAuthRequestValidator(RequestValidator):
    """Subclass of Request Validator.

    :param clientgetter: a function to get client object
    :param tokengetter: a function to get access token
    :param tokensetter: a function to save access token
    :param grantgetter: a function to get request token
    :param grantsetter: a function to save request token
    :param noncegetter: a function to get nonce and timestamp
    :param noncesetter: a function to save nonce and timestamp
    """

    def __init__(self, clientgetter, tokengetter, tokensetter,
                 grantgetter, grantsetter, noncegetter, noncesetter,
                 verifiergetter, verifiersetter, authenticateuser, config=None):
        self._clientgetter = clientgetter
        # access token getter and setter
        self._tokengetter = tokengetter
        self._tokensetter = tokensetter
        # request token getter and setter
        self._grantgetter = grantgetter
        self._grantsetter = grantsetter
        # nonce and timestamp
        self._noncegetter = noncegetter
        self._noncesetter = noncesetter
        # verifier getter and setter
        self._verifiergetter = verifiergetter
        self._verifiersetter = verifiersetter
        # verify user
        self._authenticateuser = authenticateuser
        self._config = config or {}

    @property
    def allowed_signature_methods(self):
        return self._config.get(
            'OAUTH1_PROVIDER_SIGNATURE_METHODS', SIGNATURE_METHODS
        )

    @property
    def client_key_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH', (20, 30)
        )

    @property
    def request_token_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH', (20, 30)
        )

    @property
    def access_token_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH', (20, 30)
        )

    @property
    def nonce_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH', (20, 30)
        )

    @property
    def verifier_length(self):
        return self._config.get(
            'OAUTH1_PROVIDER_KEY_LENGTH', (20, 30)
        )

    @property
    def realms(self):
        return self._config.get('OAUTH1_PROVIDER_REALMS', [])

    @property
    def enforce_ssl(self):
        return self._config.get('OAUTH1_PROVIDER_ENFORCE_SSL', True)

    @property
    def dummy_client(self):
        return to_unicode('dummy_client', 'utf-8')

    @property
    def dummy_request_token(self):
        return to_unicode('dummy_request_token', 'utf-8')

    @property
    def dummy_access_token(self):
        return to_unicode('dummy_access_token', 'utf-8')

    def get_client_secret(self, client_key, request):
        log.debug('Get client secret of %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if request.client:
            return request.client.client_secret
        return None

    def get_request_token_secret(self, client_key, token, request):
        log.debug('Get request token secret of %r for %r', token, client_key)
        tok = request.request_token or self._grantgetter(token=token)
        if tok and tok.client_key == client_key:
            request.request_token = tok
            return tok.secret
        return None

    def get_access_token_secret(self, client_key, token, request):
        log.debug('Get access token secret of %r for %r', token, client_key)
        tok = request.access_token or self._tokengetter(
            client_key=client_key,
            token=token,
        )
        if tok:
            request.access_token = tok
            return tok.secret
        return None

    def get_default_realms(self, client_key, request):
        """Default realms of the client."""
        log.debug('Get realms for %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        client = request.client
        if hasattr(client, 'default_realms'):
            return client.default_realms
        return []

    def get_realms(self, token, request):
        """Realms for this request token."""
        log.debug('Get realms of %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        if not tok:
            return []
        request.request_token = tok
        if hasattr(tok, 'realms'):
            return tok.realms or []
        return []

    def get_redirect_uri(self, token, request):
        """Redirect uri for this request token."""
        log.debug('Get redirect uri of %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        return tok.redirect_uri

    def get_rsa_key(self, client_key, request):
        """Retrieves a previously stored client provided RSA key."""
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if hasattr(request.client, 'rsa_key'):
            return request.client.rsa_key
        return None

    def invalidate_request_token(self, client_key, request_token, request):
        """Invalidates a used request token."""

    def validate_client_key(self, client_key, request):
        """Validates that supplied client key."""
        log.debug('Validate client key for %r', client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if request.client:
            return True
        return False

    def validate_request_token(self, client_key, token, request):
        """Validates request token is available for client."""
        log.debug('Validate request token %r for %r',
                  token, client_key)
        tok = request.request_token or self._grantgetter(token=token)
        if tok and tok.client_key == client_key:
            request.request_token = tok
            return True
        return False

    def validate_access_token(self, client_key, token, request):
        """Validates access token is available for client."""
        log.debug('Validate access token %r for %r',
                  token, client_key)
        tok = request.access_token or self._tokengetter(
            client_key=client_key,
            token=token,
        )
        if tok:
            request.access_token = tok
            return True
        return False

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
                                     request, request_token=None, access_token=None):
        log.debug('Validate timestamp and nonce %r', client_key)
        nonce_exists = self._noncegetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        if nonce_exists:
            return False
        self._noncesetter(
            client_key=client_key, timestamp=timestamp,
            nonce=nonce, request_token=request_token,
            access_token=access_token
        )
        return True

    def validate_redirect_uri(self, client_key, redirect_uri, request):

        """Validate if the redirect_uri is allowed by the client."""
        log.debug('Validate redirect_uri %r for %r', redirect_uri, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)
        if not request.client:
            return False
        if not request.client.redirect_uris and redirect_uri is None:
            return True
        request.redirect_uri = redirect_uri
        return redirect_uri in request.client.redirect_uris

    def validate_requested_realms(self, client_key, realms, request):
        log.debug('Validate requested realms %r for %r', realms, client_key)
        if not request.client:
            request.client = self._clientgetter(client_key=client_key)

        client = request.client
        if not client:
            return False

        if hasattr(client, 'validate_realms'):
            return client.validate_realms(realms)
        if set(client.default_realms).issuperset(set(realms)):
            return True
        return True

    def validate_realms(self, client_key, token, request, uri=None,
                        realms=None):
        """Check if the token has permission on those realms."""
        log.debug('Validate realms %r for %r', realms, client_key)
        if request.access_token:
            tok = request.access_token
        else:
            tok = self._tokengetter(client_key=client_key, token=token)
            request.access_token = tok
        if not tok:
            return False
        return set(tok.realms).issuperset(set(realms))

    def validate_verifier(self, client_key, token, verifier, request):
        """Validate verifier exists."""
        log.debug('Validate verifier %r for %r', verifier, client_key)
        data = self._verifiergetter(verifier=verifier, token=token)
        if not data:
            return False
        if not hasattr(data, 'user_id'):
            log.debug('Verifier should has user attribute')
            return False
        request.user_id = data.user_id.id
        if hasattr(data, 'client_key'):
            return data.client_key == client_key
        return True

    def verify_request_token(self, token, request):
        """Verify if the request token is existed."""
        log.debug('Verify request token %r', token)
        tok = request.request_token or self._grantgetter(token=token)
        if tok:
            request.request_token = tok
            return True
        return False

    def verify_realms(self, token, realms, request):
        """Verify if the realms match the requested realms."""
        log.debug('Verify realms %r', realms)
        tok = request.request_token or self._grantgetter(token=token)
        if not tok:
            return False

        request.request_token = tok
        if not hasattr(tok, 'realms'):
            # realms not enabled
            return True
        return set(tok.realms) == set(realms)

    def save_access_token(self, token, request):
        log.debug('Save access token %r', token)
        self._tokensetter(token, request)

    def save_request_token(self, token, request):
        log.debug('Save request token %r', token)
        self._grantsetter(token, request)

    def save_verifier(self, token, verifier, request):
        log.debug('Save verifier %r for %r', verifier, token)
        self._verifiersetter(
            token=token, verifier=verifier, request=request
        )

    def authenticate_user(self, username, password):
        return self._authenticateuser(username=username, password=password)
