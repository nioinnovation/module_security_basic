from nio.modules.context import ModuleContext
from nio.modules.settings import Settings
from nio.modules.security.module import SecurityModule
from nio import discoverable

from .authenticator import Authenticator
from .authorizer import Authorizer


@discoverable
class BasicSecurityModule(SecurityModule):

    def initialize(self, context):
        super().initialize(context)
        self.proxy_authenticator_class(Authenticator)
        self.proxy_authorizer_class(Authorizer)

        Authenticator._configure_users(context.users)
        Authenticator._configure_unhashed(context.allow_unhashed_passwords)
        Authorizer._configure_permissions(context.permissions)

    def _prepare_common_context(self):
        context = ModuleContext()

        context.users = \
            Settings.getdict('security', 'users', fallback="etc/users.json")
        context.permissions = \
            Settings.getdict('security',
                             'permissions', fallback="etc/permissions.json")
        context.allow_unhashed_passwords = \
            Settings.getboolean('security',
                                'allow_unhashed_passwords', fallback=True)

        return context

    def prepare_core_context(self):
        return self._prepare_common_context()

    def prepare_service_context(self, service_context=None):
        return self._prepare_common_context()
