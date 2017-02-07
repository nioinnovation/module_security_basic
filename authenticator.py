"""

  Basic Auth support

"""
from nio.modules.web.http import Request
from nio.modules.security.authorizer import Unauthorized
from nio.modules.security.user import User
from nio.util.logging import get_nio_logger

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
        """ Authenticates a request expecting a basic authorization header

        Args:
            request (Request): web request

        Raises:
            Unauthorized
        """
        if not isinstance(request, Request):
            raise Unauthorized("Invalid request")

        # validate that header is provided
        auth_header = request.get_header('authorization')
        if auth_header is None:
            msg = "No 'Authorization' header present in request."
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        # extract scheme and parameters from header
        try:
            scheme, params = auth_header.split(' ', 1)
        except:
            msg = "'Authorization' header is invalid."
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        # validate scheme
        if scheme.lower() != 'basic':
            msg = "'Authorization' scheme: {} is invalid, " \
                  "expected 'basic'.".format(scheme)
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        # extract username and password
        try:
            username, password = base64_decode(params).split(':', 1)
        except:
            msg = "Username and Password could not be decoded"
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        # make sure username is valid
        user = cls._users.get(username)
        if user is None:
            msg = "User: {} is invalid.".format(username)
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        # check password
        if base64_encode(password) != user.get('password'):
            msg = "Password is invalid."
            get_nio_logger("Basic.Authenticator").error(msg)
            raise Unauthorized(msg)

        return User(name=username)
