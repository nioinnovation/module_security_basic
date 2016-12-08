from nio.modules.security.authorizer import Unauthorized
from nio.modules.security.user import User
from nio.modules.security.task import SecureTask
from nio.modules.security.permissions.permissions import Permissions


class Authorizer(object):

    _permissions = {}
    _no_permissions = Permissions()

    @classmethod
    def _configure_permissions(cls, permissions):
        # store the resulting parsed permissions for each username
        cls._permissions = \
            {username: Permissions({"permissions": user_permissions})
             for username, user_permissions in permissions.items()}

    @classmethod
    def authorize(cls, user, task):
        if not isinstance(user, User) or not isinstance(task, SecureTask):
            raise Unauthorized()

        perms = cls._get_permissions_for_user(user.name)
        # See if the permission we are checking is in the user's
        # permission set
        if perms.get(task.permission, *task.resource.split(".")):
            # The permission matches, return indicating they are
            # authorized
            return

        # Didn't find the permission, guess we're not authorized
        raise Unauthorized()

    @classmethod
    def _get_permissions_for_user(cls, username):
        """ Function to return permissions for a user
        """
        return cls._permissions.get(username, cls._no_permissions)
