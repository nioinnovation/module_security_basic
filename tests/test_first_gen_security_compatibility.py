from nio.modules.context import ModuleContext
from nio.testing.test_case import NIOTestCase
from nio.modules.security.user import User
from nio.modules.security.task import SecureTask
from nio.modules.security.authorizer import Authorizer, Unauthorized

from ..module import BasicSecurityModule


class TestFirstGenPermissions(NIOTestCase):

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
            context.permissions = {
                "user1": ['*']
            }
            return context
        else:
            return super().get_context(module_name, module)

    def test_first_gen_permissions(self):
        """ Tests user1 can do anything """
        user = User("user1")
        Authorizer.authorize(user, SecureTask("services", "read"))
        Authorizer.authorize(user, SecureTask("services", "write"))
        Authorizer.authorize(user, SecureTask("services", "execute"))

        Authorizer.authorize(user, SecureTask("any_resource", "read"))
        Authorizer.authorize(user, SecureTask("any_resource", "write"))
        Authorizer.authorize(user, SecureTask("any_resource", "execute"))

        # actual permissions have to be valid
        with self.assertRaises(Unauthorized):
            Authorizer.authorize(user, SecureTask("any_resource", "invalid"))
