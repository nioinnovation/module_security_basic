from nio.modules.context import ModuleContext
from nio.testing.test_case import NIOTestCase
from nio.modules.security.user import User, CoreServiceAccount
from nio.modules.security.task import SecureTask
from nio.modules.security.authorizer import Authorizer, Unauthorized

from ..module import BasicSecurityModule


class TestBasicAuthorization(NIOTestCase):

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
            context.users = {}
            context.allow_unhashed_passwords = True
            context.permissions = {
                "user1": {"services": "r", "blocks": "r"},
                "user3": {}
            }
            return context
        else:
            return super().get_context(module_name, module)

    def test_basic_permissions(self):
        """ Tests the basic permission matching """
        user = User("user1")
        Authorizer.authorize(user, SecureTask("services", "read"))
        Authorizer.authorize(user, SecureTask("blocks", "read"))
        with self.assertRaises(Unauthorized):
            Authorizer.authorize(user, SecureTask("services", "execute"))

    def test_no_permissions(self):
        """ Tests that a user with no permissions is Unauthorized """
        user = User("user3")
        with self.assertRaises(Unauthorized):
            Authorizer.authorize(user, SecureTask("blocks", "read"))

    def test_nonexistent_user(self):
        """ Tests that a user who doesn't exist is Unauthorized """
        user = User("not a user")
        with self.assertRaises(Unauthorized):
            Authorizer.authorize(user, SecureTask("blocks", "read"))

    def test_invalid_authorize(self):
        """ Tests that authorize must be called with the right types """
        with self.assertRaises(Unauthorized):
            Authorizer.authorize("just a username", SecureTask("r", "p"))
        with self.assertRaises(Unauthorized):
            Authorizer.authorize(User(), "just a task string")

    def test_core_service_authorized(self):
        """Make sure a CoreServiceAccount can do anything"""
        Authorizer.authorize(
            CoreServiceAccount(), SecureTask("blocks", "write"))
