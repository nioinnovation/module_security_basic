"""

  Basic Auth support

"""
from nio.modules.web.http import Request
from nio.modules.security.authorizer import Unauthorized
from nio.modules.security.user import User
from .base64 import base64_decode, base64_encode


class Authenticator(object):

    """  Authenticator that handles Basic Authentication

    Retrieves a user based on user/password passed in the authentication
    header. This header is base64 encoded

    """

    @classmethod
    def _configure_users(cls, users):
        cls._users = users

    @classmethod
    def authenticate(cls, request):
        if not isinstance(request, Request):
            raise Unauthorized("Invalid request")

        auth_header = request.get_header('authorization')
        if auth_header is None:
            # No header, assume guest
            return User()
        try:
            scheme, params = auth_header.split(' ', 1)
            if scheme.lower() == 'basic':
                username, password = base64_decode(params).split(':', 1)
                user = cls._users.get(username)
                if user is not None and \
                        base64_encode(password) == user.get('password'):
                    return User(name=username)
        except:
            raise Unauthorized()
        raise Unauthorized()
