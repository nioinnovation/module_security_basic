from unittest.mock import MagicMock
from bcrypt import hashpw, gensalt

from nio.modules.context import ModuleContext
from ..base64 import base64_encode
from nio.testing.test_case import NIOTestCase
from nio.modules.security.authorizer import Unauthorized
from nio.modules.security.authenticator import Authenticator
from nio.modules.web.http import Request

from ..module import BasicSecurityModule


class TestBasicAuthentication(NIOTestCase):

    def get_test_modules(self):
        return super().get_test_modules() | {'security'}

    def get_module(self, module_name):
        if module_name == 'security':
            return BasicSecurityModule()
        else:
            return super().get_module(module_name)

    def get_context(self, module_name, module):
        if module_name == 'security':
            context = ModuleContext()
            context.users = {
                "TestName": {"password": base64_encode("TestPass")},
                "HashName": {
                    "password": hashpw(b'HashPass', gensalt()).decode()}
            }
            context.allow_unhashed_passwords = True
            context.permissions = {}
            return context
        else:
            return super().get_context(module_name, module)

    def test_basic_auth(self):
        """ Test simple basic auth """
        request = MagicMock(spec=Request)
        request.get_header.return_value = "Basic {}".format(
            base64_encode("TestName:TestPass"))
        user = Authenticator.authenticate(request=request)
        self.assertEqual('TestName', user.name)

    def test_basic_auth_invalid_pass(self):
        """ Test simple basic auth with the wrong password """
        request = MagicMock(spec=Request)
        request.get_header.return_value = "Basic {}".format(
            base64_encode("TestName:WrongPass"))
        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)

    def test_hashed_basic_auth(self):
        """ Test basic auth with hashed password """
        request = MagicMock(spec=Request)
        request.get_header.return_value = "Basic {}".format(
            base64_encode("HashName:HashPass"))
        user = Authenticator.authenticate(request=request)
        self.assertEqual('HashName', user.name)

    def test_hashed_basic_auth_invalid_pass(self):
        """ Test basic auth with wrong hashed password """
        request = MagicMock(spec=Request)
        request.get_header.return_value = "Basic {}".format(
            base64_encode("HashName:WrongPass"))
        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)

    def test_header_missing(self):
        """ Test missing authorization header.

        Raises Unauthorized.
        """
        request = MagicMock(spec=Request)
        request.get_header.return_value = None

        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)

    def test_bad_header(self):
        """ Test wrong header value
        """
        request = MagicMock(spec=Request)
        request.get_header.return_value = "Basicfffff"
        with self.assertRaises(Unauthorized):
            Authenticator.authenticate(request=request)
