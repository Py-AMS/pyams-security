#
# Copyright (c) 2015-2019 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.interfaces module

This module provides all security-related constants and interfaces.
"""

from zope.annotation import IAttributeAnnotatable
from zope.container.constraints import contains
from zope.container.interfaces import IContainer
from zope.interface import Attribute, Interface, implementer
from zope.interface.interfaces import IObjectEvent, ObjectEvent
from zope.schema import Bool, TextLine, Tuple

from pyams_security.interfaces.names import PASSWORD_MANAGERS_VOCABULARY_NAME, \
    USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.interfaces.plugin import IDirectoryPluginInfo, IPlugin, IPluginEvent
from pyams_security.schema import PermissionsSetField

__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


#
# Roles events interfaces
#

class IRoleEvent(IObjectEvent):
    """Base role event interface"""

    role_id = Attribute("Modified role ID")

    principal_id = Attribute("Modified principal ID")


@implementer(IRoleEvent)
class RoleEvent(ObjectEvent):
    """Base role event"""

    def __init__(self, object, role_id, principal_id):  # pylint: disable=redefined-builtin
        super().__init__(object)
        self.role_id = role_id
        self.principal_id = principal_id


class IGrantedRoleEvent(IRoleEvent):
    """Granted role event interface"""


@implementer(IGrantedRoleEvent)
class GrantedRoleEvent(RoleEvent):
    """Granted role event"""


class IRevokedRoleEvent(IRoleEvent):
    """Revoked role event interface"""


@implementer(IRevokedRoleEvent)
class RevokedRoleEvent(RoleEvent):
    """Revoked role interface"""


#
# Security manager
#

class ISecurityManager(IContainer, IDirectoryPluginInfo, IAttributeAnnotatable):
    """Authentication and principals management utility"""

    contains(IPlugin)

    credentials_plugins_names = Tuple(title=_("Credentials plug-ins"),
                                      description=_("These plug-ins are used to extract "
                                                    "credentials from an incoming request (the "
                                                    "Pyramid session plug-in is built-in!). "
                                                    "They can rely on authentication plug-ins "
                                                    "to ensure that provided credentials are "
                                                    "valid..."),
                                      value_type=TextLine(),
                                      readonly=True)

    authentication_plugins_names = Tuple(title=_("Authentication plug-ins"),
                                         description=_("The plug-ins can be used to check "
                                                       "extracted credentials against a local or "
                                                       "remote users database"),
                                         value_type=TextLine(),
                                         default=())

    directory_plugins_names = Tuple(title=_("Directory plug-ins"),
                                    description=_("The plug-in can be used to extract principals "
                                                  "information"),
                                    value_type=TextLine(),
                                    default=())

    def get_plugin(self, name):
        """Get plug-in matching given name"""

    credentials_plugins = Attribute("Iterator on registered credentials plug-ins")

    authentication_plugins = Attribute("Iterator on registered and local authentication plug-ins")

    directory_plugins = Attribute("Iterator on registered and local directory plug-ins")

    groups_directory_plugins = Attribute("Iterator on registered and local groups plug-ins")

    def extract_credentials(self, request, **kwargs):
        """Extract credentials from request"""

    def authenticate(self, credentials, request, get_plugin_name=False, get_plugin=False):
        """Try to authenticate request with given credentials"""

    def authenticated_userid(self, request, principal_id=None):
        """Extract authenticated user ID from request"""

    def effective_principals(self, principal_id):
        """Get effective principals of provided principal ID"""

    def get_principal(self, principal_id, info=True):
        """Principal lookup for provided principal ID"""

    def get_raw_principal(self, principal_id):
        """Principal lookup for provided principal ID

        Unlike *get_principal* method, this one will always return a
        *raw* principal, instead of a generic principal info, and *None*
        if the principal can't be found.
        """

    def get_all_principals(self, principal_id):
        """Get all principals of given principal ID"""

    def find_principals(self, query, exact_match=False):
        """Find principals matching given query"""

    show_home_menu = Bool(title=_("Access menu from home"),
                          description=_("If 'yes', a menu will be displayed to get access to "
                                        "security manager from site admin home page"),
                          required=True,
                          default=False)


class IPrincipalsGetter(Interface):
    """Principals getter

    This multi-interfaces adapter is used by security policy to get custom principals,
    for example to get principal roles.
    """

    def get_principals(self, principal_id):
        """Get custom principals matching given arguments"""


class IRolesGetter(Interface):
    """Roles getter

    This multi-interfaces adapter is used by security policy to get roles of principals,
    which roles will be added to initial principals roles.
    """

    def get_roles(self, principals):
        """Get set of roles associated with given principals"""


LOGIN_REFERER_KEY = 'pyams_security.login.referer'
"""Key of request annotation used to store referer"""


#
# Protected objects interfaces
#

class IProtectedObject(IAttributeAnnotatable):
    """Protected object interface

    This is the only interface used by authorization policy.
    So you are free to implement custom protection mechanisms.
    """

    inherit_parent_security = Bool(title=_("Inherit parent security?"),
                                   description=_("Get access control entries (ACE) inherited "
                                                 "from parent levels"),
                                   required=True,
                                   default=True)

    everyone_denied = PermissionsSetField(title=_("Public denied permissions"),
                                          description=_("These permissions will be denied to all "
                                                        "users. Denied permissions take "
                                                        "precedence over granted ones."),
                                          required=False)

    everyone_granted = PermissionsSetField(title=_("Public granted permissions"),
                                           description=_("These permissions will be granted to "
                                                         "all users"),
                                           required=False)

    authenticated_denied = PermissionsSetField(title=_("Authenticated denied permissions"),
                                               description=_("These permissions will be denied "
                                                             "to authenticated users. Denied "
                                                             "permissions take precedence over "
                                                             "granted ones."),
                                               required=False)

    authenticated_granted = PermissionsSetField(title=_("Authenticated granted permissions"),
                                                description=_("These permissions will be granted "
                                                              "to authenticated users"),
                                                required=False)

    inherit_parent_roles = Bool(title=_("Inherit parent roles?"),
                                description=_("Get roles granted on parent levels"),
                                required=True,
                                default=True)

    def __acl__(self):
        """Object ACL"""

    def get_principals(self, role_id):
        """Get ID of principals who were granted given role

        May return an empty set when empty
        """

    def get_roles(self, principal_id):
        """Get ID of roles granted to given principal

        May return an empty set when empty
        """

    def get_roles_ids(self, principal_id):
        """Get ID of roles granted to given principal"""

    def get_permissions(self, principal_id):
        """Get ID of permissions granted to given principal"""

    def get_everyone_denied(self):
        """Get denied permissions for everyone, including inherited ones"""

    def get_everyone_granted(self):
        """Get granted permissions for everyone, including inherited ones"""

    def get_authenticated_denied(self):
        """Get denied permissions for authenticated, including inherited ones"""

    def get_authenticated_granted(self):
        """Get granted permissions for authenticated, including inherited ones"""

    def get_granted_roles(self):
        """Get all roles, including inherited ones"""


class IRoleProtectedObject(IProtectedObject):
    """Roles protected object interface"""

    def grant_role(self, role, principal_ids):
        """Grant given role to principals"""

    def revoke_role(self, role, principal_ids):
        """Revoke given role from principals"""


class IDefaultProtectionPolicy(Interface):
    """Marker interface for objects using default protection policy"""


class IContentRoles(Interface):
    """Base content roles interface"""


class IRolesPolicy(Interface):
    """Roles policy interface"""

    roles_interface = Attribute("Name of interface containing roles fields")

    weight = Attribute("Weight ordering attribute")


class ISecurityContext(Interface):
    """Security context getter interface

    This interface may be used as a simple context adapter to get object from
    which security permissions should be extracted.
    """


class IViewContextPermissionChecker(Interface):
    """Interface used to check access permissions on view context

    May be implemented as a context adapter, or as a (context, request, view)
    multi-adapter.
    """

    edit_permission = Attribute("Permission required to update form's content")
