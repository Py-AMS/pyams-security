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

import re

from zope.annotation import IAttributeAnnotatable
from zope.container.constraints import containers, contains
from zope.container.interfaces import IContainer
from zope.interface import Attribute, Interface, implementer, invariant
from zope.interface.interfaces import IObjectEvent, Invalid, ObjectEvent
from zope.location.interfaces import IContained
from zope.schema import Bool, Choice, Datetime, Dict, Int, List, Set, Text, TextLine, Tuple

from pyams_security.interfaces.names import OAUTH_PROVIDERS_VOCABULARY_NAME, \
    OAUTH_USERS_FOLDERS_VOCABULARY_NAME, PASSWORD_MANAGERS_VOCABULARY_NAME, \
    USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.schema import PermissionsSetField, PrincipalsSetField
from pyams_utils.schema import EncodedPasswordField


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


#
# Package constants
#

SYSTEM_PREFIX = 'system'

ADMIN_USER_NAME = '__system__'
ADMIN_USER_LOGIN = 'admin'
ADMIN_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, ADMIN_USER_LOGIN)

INTERNAL_USER_NAME = '__internal__'
INTERNAL_USER_LOGIN = 'internal'
INTERNAL_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, INTERNAL_USER_LOGIN)

SYSTEM_ADMIN_ROLE = 'system.Manager'


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
        super(RoleEvent, self).__init__(object)
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
# Security plug-ins interfaces
#

class IPlugin(IContained, IAttributeAnnotatable):
    """Basic authentication plug-in interface"""

    containers('pyams_security.interfaces.IAuthentication')

    prefix = TextLine(title=_("Plug-in prefix"),
                      description=_("This prefix is mainly used by authentication plug-ins to "
                                    "mark principals"))

    title = TextLine(title=_("Plug-in title"),
                     required=False)

    enabled = Bool(title=_("Enabled plug-in?"),
                   description=_("You can choose to disable any plug-in..."),
                   required=True,
                   default=True)


class IPluginEvent(Interface):
    """Plug-in event interface"""

    plugin = Attribute("Event plug-in name")


#
# Credentials extraction plug-ins interfaces
#

class ICredentials(Interface):
    """Credentials interface"""

    prefix = TextLine(title="Credentials plug-in prefix",
                      description="Prefix of plug-in which extracted credentials")

    id = TextLine(title="Credentials ID")  # pylint: disable=invalid-name

    attributes = Dict(title="Credentials attributes",
                      description="Attributes dictionary defined by each credentials plug-in",
                      required=False,
                      default={})


class ICredentialsPluginInfo(Interface):
    """Credentials extraction plug-in base interface"""

    def extract_credentials(self, request):
        """Extract user credentials from given request

        Result of 'extract_credentials' call should be an ICredentials object for which
        id is the 'raw' principal ID (without prefix); only authentication plug-ins should
        add a prefix to principal IDs to distinguish principals
        """


class ICredentialsPlugin(ICredentialsPluginInfo, IPlugin):
    """Credentials extraction plug-in interface"""


#
# Authentication plug-ins interfaces
#

class IAuthenticationPluginInfo(Interface):
    """Principal authentication plug-in base interface"""

    def authenticate(self, credentials, request):
        """Authenticate given credentials and returns a principal ID or None"""


class IAuthenticationPlugin(IAuthenticationPluginInfo, IPlugin):
    """Principal authentication plug-in interface"""


class IAdminAuthenticationPlugin(IAuthenticationPlugin):
    """Admin authentication plug-in base interface"""

    login = TextLine(title=_("Admin. login"))

    password = EncodedPasswordField(title=_("Admin. password"),
                                    required=False)


class IAuthenticatedPrincipalEvent(IPluginEvent):
    """Authenticated principal event interface"""

    principal_id = Attribute("Authenticated principal ID")

    infos = Attribute("Event custom infos")


@implementer(IAuthenticatedPrincipalEvent)
class AuthenticatedPrincipalEvent:
    """Authenticated principal event"""

    def __init__(self, plugin, principal_id, **infos):
        self.plugin = plugin
        self.principal_id = principal_id
        self.infos = infos


#
# Directory plug-ins interfaces
#

class IDirectoryPluginInfo(Interface):
    """Principal directory plug-in interface"""

    def get_principal(self, principal_id, info=True):
        """Returns real principal matching given ID, or None

        If info is True, returns a PrincipalInfo record instead
        of original principal object
        """

    def get_all_principals(self, principal_id):
        """Returns all principals matching given principal ID"""

    def find_principals(self, query):
        """Find principals matching given query

        Method may return an iterator
        """


class IDirectoryPlugin(IDirectoryPluginInfo, IPlugin):
    """Principal directory plug-in info"""


class IDirectorySearchPlugin(IDirectoryPlugin):
    """Principal directory plug-in supporting search"""

    def get_search_results(self, data):
        """Search principals matching given query data

        This method is used in back-office search views so may reply even
        when the plug-in is disabled.
        Method may return an iterator on his own content objects
        """


class IGroupsAwareDirectoryPlugin(Interface):
    """Marker interface for plug-ins handling groups"""


#
# OAuth users interfaces
#

class IOAuthUsersFolderPlugin(IDirectorySearchPlugin):
    """OAuth users folder interface"""

    contains('pyams_security.interfaces.IOAuthUser')


class IOAuthUser(IAttributeAnnotatable):
    """OAuth user interface"""

    containers(IOAuthUsersFolderPlugin)

    user_id = TextLine(title=_("Internal provider ID"))

    provider_name = TextLine(title=_("OAuth provider name"))

    username = TextLine(title=_("User name"),
                        required=False)

    name = TextLine(title=_("Name"))

    first_name = TextLine(title=_('First name'),
                          required=False)

    last_name = TextLine(title=_('Last name'),
                         required=False)

    nickname = TextLine(title=_('Nickname'),
                        required=False)

    email = TextLine(title=_("E-mail address"),
                     required=False)

    timezone = TextLine(title=_('Timezone'),
                        required=False)

    country = TextLine(title=_('Country'),
                       required=False)

    city = TextLine(title=_('City'),
                    required=False)

    postal_code = TextLine(title=_("Postal code"),
                           required=False)

    locale = TextLine(title=_('Locale code'),
                      required=False)

    picture = TextLine(title=_('Picture URL'),
                       required=False)

    birth_date = Datetime(title=_('Birth date'),
                          required=False)

    registration_date = Datetime(title=_("Registration date"),
                                 readonly=True)


#
# User local registration
#

class IUsersFolderPlugin(IAuthenticationPlugin, IDirectorySearchPlugin):
    """Local users folder interface"""

    contains('pyams_security.interfaces.ILocalUser')

    def check_login(self, login):
        """Check for existence of given login"""


MAJS = range(ord('A'), ord('Z') + 1)
MINS = range(ord('a'), ord('z') + 1)
NUMS = range(ord('0'), ord('9') + 1)


def check_password(password):
    """Check validity of a given password"""
    nbmaj = 0
    nbmin = 0
    nbn = 0
    nbo = 0
    for car in password:
        if ord(car) in MAJS:
            nbmaj += 1
        elif ord(car) in MINS:
            nbmin += 1
        elif ord(car) in NUMS:
            nbn += 1
        else:
            nbo += 1
    if [nbmin, nbmaj, nbn, nbo].count(0) > 1:
        raise Invalid(_("Your password must contain at least three of these kinds of characters: "
                        "lowercase letters, uppercase letters, numbers and special characters"))


EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")


class IUserRegistrationInfo(Interface):
    """User registration info"""

    login = TextLine(title=_("User login"),
                     description=_("If you don't provide a custom login, your login will be your "
                                   "email address..."),
                     required=False)

    @invariant
    def check_login(self):
        """Set login as mail when missing"""
        if not self.login:
            self.login = self.email

    email = TextLine(title=_("E-mail address"),
                     description=_("An email will be sent to this address to validate account "
                                   "activation; it will be used as your future user login"),
                     required=True)

    @invariant
    def check_email(self):
        """Check for valid email"""
        if not EMAIL_REGEX.match(self.email):
            raise Invalid(_("Your email address is not valid!"))

    firstname = TextLine(title=_("First name"),
                         required=True)

    lastname = TextLine(title=_("Last name"),
                        required=True)

    company_name = TextLine(title=_("Company name"),
                            required=False)

    password = EncodedPasswordField(title=_("Password"),
                                    description=_("Password must be at least 8 characters long, "
                                                  "and contain at least three kinds of characters "
                                                  "between lowercase letters, uppercase letters, "
                                                  "numbers and special characters"),
                                    min_length=8,
                                    required=True)

    confirmed_password = EncodedPasswordField(title=_("Confirmed password"),
                                              required=True)

    @invariant
    def check_password(self):
        """Check for password confirmation"""
        if self.password != self.confirmed_password:
            raise Invalid(_("You didn't confirmed your password correctly!"))
        check_password(self.password)


class IUserRegistrationConfirmationInfo(Interface):
    """User registration confirmation info"""

    activation_hash = TextLine(title=_("Activation hash"),
                               required=True)

    login = TextLine(title=_("User login"),
                     required=True)

    password = EncodedPasswordField(title=_("Password"),
                                    min_length=8,
                                    required=True)

    confirmed_password = EncodedPasswordField(title=_("Confirmed password"),
                                              required=True)

    @invariant
    def check_password(self):
        """Check for password confirmation"""
        if self.password != self.confirmed_password:
            raise Invalid(_("You didn't confirmed your password correctly!"))
        check_password(self.password)


class ILocalUser(IAttributeAnnotatable):
    """Local user interface"""

    containers(IUsersFolderPlugin)

    login = TextLine(title=_("User login"),
                     required=True,
                     readonly=True)

    @invariant
    def check_login(self):
        """Set login as mail when missing"""
        if not self.login:
            self.login = self.email

    email = TextLine(title=_("User email address"),
                     required=True)

    @invariant
    def check_email(self):
        """Check for invalid email address"""
        if not EMAIL_REGEX.match(self.email):
            raise Invalid(_("Given email address is not valid!"))

    firstname = TextLine(title=_("First name"),
                         required=True)

    lastname = TextLine(title=_("Last name"),
                        required=True)

    title = Attribute("User full name")

    company_name = TextLine(title=_("Company name"),
                            required=False)

    password_manager = Choice(title=_("Password manager name"),
                              required=True,
                              vocabulary=PASSWORD_MANAGERS_VOCABULARY_NAME,
                              default='SSHA')

    password = EncodedPasswordField(title=_("Password"),
                                    min_length=8,
                                    required=False)

    wait_confirmation = Bool(title=_("Wait confirmation?"),
                             description=_("If 'no', user will be activated immediately without "
                                           "waiting email confirmation"),
                             required=True,
                             default=True)

    self_registered = Bool(title=_("Self-registered profile?"),
                           required=True,
                           default=True,
                           readonly=True)

    activation_secret = TextLine(title=_("Activation secret key"),
                                 description=_("This private secret is used to create and check "
                                               "activation hash"),
                                 readonly=True)

    activation_hash = TextLine(title=_("Activation hash"),
                               description=_("This hash is provided into activation message URL. "
                                             "Activation hash is missing for local users which "
                                             "were registered without waiting their confirmation."),
                               readonly=True)

    activation_date = Datetime(title=_("Activation date"),
                               required=False)

    activated = Bool(title=_("Activation date"),
                     required=True,
                     default=False)

    def check_password(self, password):
        """Check user password against provided one"""

    def generate_secret(self, login, password):
        """Generate secret key of this profile"""

    def check_activation(self, hash, login, password):  # pylint: disable=redefined-builtin
        """Check activation for given settings"""

    def to_dict(self):
        """Get main user properties as mapping"""


#
# Principals groups
#

class IGroupsFolderPlugin(IDirectorySearchPlugin, IGroupsAwareDirectoryPlugin):
    """Principals groups folder plug-in"""

    contains('pyams_security.interfaces.ILocalGroup')

    def check_group_id(self, group_id):
        """Check for existence of given group ID"""


class ILocalGroup(Interface):
    """Local principals group interface"""

    containers(IGroupsFolderPlugin)

    group_id = TextLine(title=_("Group ID"),
                        description=_("This ID should be unique between all groups"),
                        required=True,
                        readonly=True)

    title = TextLine(title=_("Title"),
                     description=_("Public label of this group"),
                     required=True)

    description = Text(title=_("Description"),
                       required=False)

    principals = PrincipalsSetField(title=_("Group principals"),
                                    description=_("IDs of principals contained in this group"),
                                    required=False,
                                    default=set())


class IPrincipalsGroupEvent(Interface):
    """Principals group event interface"""

    group = Attribute("Event source group")

    principals = Set(title="List of principals IDs",
                     value_type=TextLine())


class PrincipalsGroupEvent:
    """Principals group event"""

    def __init__(self, group, principals):
        self.group = group
        self.principals = principals


class IPrincipalsAddedToGroupEvent(IPrincipalsGroupEvent):
    """Interface of event fired when principals were added to group"""


@implementer(IPrincipalsAddedToGroupEvent)
class PrincipalsAddedToGroupEvent(PrincipalsGroupEvent):
    """Event fired when principals were added to group"""


class IPrincipalsRemovedFromGroupEvent(IPrincipalsGroupEvent):
    """Interface of event fired when principals were removed from group"""


@implementer(IPrincipalsRemovedFromGroupEvent)
class PrincipalsRemovedFromGroupEvent(PrincipalsGroupEvent):
    """Event fired when principals were removed from group"""


#
# Security manager
#

class ISecurityManager(IContainer, IDirectoryPluginInfo, IAttributeAnnotatable):
    """Authentication and principals management utility"""

    contains(IPlugin)

    enable_jwt_login = Bool(title=_("Enable JWT login?"),
                            description=_("Enable login via JWT authentication"),
                            required=False,
                            default=False)

    jwt_algorithm = Choice(title=_("JWT encoding algorithm"),
                           description=_(""),
                           required=False,
                           values=('RS256', 'RS512', 'HS256', 'HS512'),
                           default='RS512')

    jwt_secret = TextLine(title=_("JWT secret"),
                          description=_("This secret is required when using HS* encryption"),
                          required=False)

    jwt_private_key = Text(title=_("JWT private key"),
                           description=_("The secret key is required when using RS* algorithm"),
                           required=False)

    jwt_public_key = Text(title=_("JWT public key"),
                          description=_("The public key is required when using RS* algorithm"),
                          required=False)

    jwt_expiration = Int(title=_("Token lifetime"),
                         description=_("JWT token lifetime, in seconds"),
                         required=False)

    @invariant
    def check_jwt(self):
        """Check for JWT configuration"""
        if self.enable_jwt_login:
            if not self.jwt_algorithm:
                raise Invalid(_("You must choose an algorithm to enable JWT authentication"))
            if self.jwt_algorithm.startswith('HS'):
                if not self.jwt_secret:
                    raise Invalid(_("You must define JWT secret to use HS256 algorithm"))
            elif self.jwt_algorithm.startswith('RS'):
                if not (self.jwt_secret_key and self.jwt_public_key):
                    raise Invalid(_("You must define a private and a public key to use RS256 "
                                    "algorithm"))

    enable_oauth_login = Bool(title=_("Enable OAuth login?"),
                              description=_("Enable login via OAuth authentication providers"),
                              required=False,
                              default=False)

    oauth_users_folder = Choice(title=_("OAuth users folder"),
                                description=_("Name of folder used to store properties of users "
                                              "authenticated with OAuth"),
                                required=False,
                                vocabulary=OAUTH_USERS_FOLDERS_VOCABULARY_NAME)

    @invariant
    def check_oauth_users_folder(self):
        """Check for OAuth configuration"""
        if self.enable_oauth_login and not self.oauth_users_folder:
            raise Invalid(_("You can't activate OAuth login without selecting an OAuth users "
                            "folder"))

    authomatic_secret = TextLine(title=_("Authomatic secret"),
                                 description=_("This secret phrase is used to encrypt Authomatic "
                                               "cookie"),
                                 default='this is not a secret',
                                 required=True)

    oauth_login_use_popup = Bool(title=_("Use OAuth popup?"),
                                 required=True,
                                 default=False)

    open_registration = Bool(title=_("Enable free registration?"),
                             description=_("If 'Yes', any use will be able to create a new user "
                                           "account"),
                             required=False,
                             default=False)

    users_folder = Choice(title=_("Users folder"),
                          description=_("Name of users folder used to store registered principals"),
                          required=False,
                          vocabulary=USERS_FOLDERS_VOCABULARY_NAME)

    @invariant
    def check_users_folder(self):
        """Check for open registration"""
        if self.open_registration and not self.users_folder:
            raise Invalid(_("You can't activate open registration without selecting a users "
                            "folder"))

    credentials_plugins_names = Tuple(title=_("Credentials plug-ins"),
                                      description=_("These plug-ins can be used to extract request "
                                                    "credentials"),
                                      value_type=TextLine(),
                                      readonly=True,
                                      default=())

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

    def effective_principals(self, principal_id, request=None, context=None):
        """Get effective principals of given principal for context"""

    def get_plugin(self, name):
        """Get plug-in matching given name"""

    def get_credentials_plugins(self):
        """Extract list of credentials plug-ins"""

    def order_credentials_plugins(self, names):
        """Define credentials plug-ins order"""

    def get_authentication_plugins(self):
        """Extract list of authentication plug-ins"""

    def order_authentication_plugins(self, names):
        """Define authentication plug-ins order"""

    def get_directory_plugins(self):
        """Extract list of directory plug-ins"""

    def order_directory_plugins(self, names):
        """Define directory plug-ins order"""


LOGIN_REFERER_KEY = 'pyams_security.login.referer'


#
# OAuth login providers configuration
#

class IOAuthLoginProviderInfo(Interface):
    """OAuth login provider info

    This interface is used to adapt providers to
    get minimum information like icon class, URLs
    required to get consumer elements...
    """

    name = TextLine(title="Provider name")

    provider = Attribute("Provider class")

    icon_class = TextLine(title="Icon class",
                          description="Fontawesome icon class",
                          required=True)

    icon_filename = TextLine(title="Color icon filename",
                             required=True)

    scope = List(title="User info scope",
                 value_type=TextLine())


class IOAuthLoginConfiguration(Interface):
    """OAuth login configuration interface"""

    contains('pyams_securiy.interfaces.IOAuthLoginProviderConnection')

    def get_oauth_configuration(self):
        """Get Authomatic configuration"""


class IOAuthLoginProviderConnection(Interface):
    """OAuth login provider info"""

    containers(IOAuthLoginConfiguration)

    provider_name = Choice(title=_("Provider name"),
                           vocabulary=OAUTH_PROVIDERS_VOCABULARY_NAME,
                           required=True)

    provider_id = Int(title=_("Provider ID"),
                      description=_("This value should be unique between all providers"),
                      required=True,
                      min=0)

    consumer_key = TextLine(title=_("Provider consumer key"),
                            required=True)

    consumer_secret = TextLine(title=_("Provider secret"),
                               required=True)

    def get_configuration(self):
        """Get provider configuration"""


#
# JWT authentication utility interface
#

class IJWTAuthenticationPlugin(IAuthenticationPlugin):
    """JWT authentication policy"""

    audience = Attribute("Token audience")
    leeway = Attribute("Token leeway")
    http_header = Attribute("HTTP header used for JWT token")
    auth_type = Attribute("JWT authentication type")
    callback = Attribute("JWT authentication callback")
    json_encoder = Attribute("JSON encoder used to encode token claims")

    def is_enabled(self):
        """Boolean value used to specify if plugin is enabled"""

    def create_token(self, principal, expiration=None, audience=None, **claims):
        """Create JWT token"""

    def get_claims(self, request):
        """Extract claims from JWT token"""

    def unauthenticated_userid(self, request):
        """User ID claimed by request credentials, if any"""


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
                                                        "users. Denied permissions take precedence "
                                                        "over granted ones."),
                                          required=False)

    everyone_granted = PermissionsSetField(title=_("Public granted permissions"),
                                           description=_("These permissions will be granted to all "
                                                         "users"),
                                           required=False)

    authenticated_denied = PermissionsSetField(title=_("Authenticated denied permissions"),
                                               description=_("These permissions will be denied to "
                                                             "authenticated users. Denied "
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
        """Grant given role to ptincipals"""

    def revoke_role(self, role, principal_ids):
        """Revoke given role from principals"""


class IDefaultProtectionPolicy(Interface):
    """Marker interface for objects using default protection policy"""

    __roles__ = Tuple(title="Content roles",
                      description="List of roles handles by this object",
                      value_type=PrincipalsSetField(),
                      required=True)

    roles_interface = Attribute("Name of interface containing roles fields")
