#
# Copyright (c) 2015-2022 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_*** module

"""

import re
from zope.annotation import IAttributeAnnotatable
from zope.container.constraints import containers, contains
from zope.interface import Attribute, Interface, Invalid, implementer, invariant
from zope.location.interfaces import IContained
from zope.schema import Bool, Choice, Datetime, Dict, Set, Text, TextLine

from pyams_security.interfaces.names import PASSWORD_MANAGERS_VOCABULARY_NAME, USER_LOGIN_TITLE
from pyams_security.schema import PrincipalsSetField
from pyams_utils.schema import EncodedPasswordField


__docformat__ = 'restructuredtext'

from pyams_security import _


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

    plugin = Attribute("Event source plug-in")


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


ADMIN_AUTHENTICATION_PLUGIN_LABEL = _("System authentication plug-in")


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

    def find_principals(self, query, exact_match=False):
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
# User local registration
#

SALT_SIZE = {
    'SSHA512': 32,
    'PBKDF2': 32
}


USERS_FOLDER_PLUGIN_LABEL = _("Users folder plug-in")


class IUsersFolderPlugin(IAuthenticationPlugin, IDirectorySearchPlugin):
    """Local users folder interface"""

    contains('pyams_security.interfaces.ILocalUser')

    case_insensitive_login = Bool(title=_("Use case insensitive login"),
                                  description=_("If enabled, users login will not be case sensitive"),
                                  required=True,
                                  default=False)

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

LOCKED_ACCOUNT_PASSWORD = '##LOCKED##'


class IUserRegistrationInfo(Interface):
    """User registration info"""

    login = TextLine(title=USER_LOGIN_TITLE,
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
                                                  "and contain at least three kinds of "
                                                  "characters between lowercase letters, "
                                                  "uppercase letters, numbers and special "
                                                  "characters"),
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

    login = TextLine(title=USER_LOGIN_TITLE,
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

    login = TextLine(title=USER_LOGIN_TITLE,
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
                              description=_("Utility used to encrypt user password"),
                              required=True,
                              vocabulary=PASSWORD_MANAGERS_VOCABULARY_NAME,
                              default='PBKDF2')

    password = EncodedPasswordField(title=_("Password"),
                                    min_length=8,
                                    required=False)

    confirmed_password = EncodedPasswordField(title=_("Confirmed password"),
                                              min_length=8,
                                              required=False)

    wait_confirmation = Bool(title=_("Wait confirmation?"),
                             description=_("If 'no', user will be activated immediately without "
                                           "waiting email confirmation"),
                             required=True,
                             default=True)

    @invariant
    def check_activated_user(self):
        """Check for missing password of activated user"""
        if not self.password and not self.wait_confirmation:
            raise Invalid(_("You can't activate an account without setting a password!"))

    self_registered = Bool(title=_("Self-registered profile?"),
                           required=True,
                           default=True,
                           readonly=True)

    activation_secret = TextLine(title=_("Activation secret key"),
                                 description=_("This private secret is used to create and check "
                                               "activation hash"))

    activation_hash = TextLine(title=_("Activation hash"),
                               description=_("This hash is provided into activation message URL. "
                                             "Activation hash is missing for local users which "
                                             "were registered without waiting their "
                                             "confirmation."))

    activated = Bool(title=_("Activated"),
                     required=True,
                     default=False)

    activation_date = Datetime(title=_("Activation date"),
                               required=False)

    password_hash = TextLine(title=_("Password reset hash"),
                             description=_("This hash is provided when a user is asking for a password "
                                           "reset; please note that password reset request should not "
                                           "update password..."),
                             required=False)

    password_hash_validity = Datetime(title=_("Password reset hash date"),
                                      required=False)

    def check_password(self, password):
        """Check user password against provided one"""

    def generate_secret(self, notify=True, request=None):
        """Generate secret key of this profile"""

    def refresh_secret(self, notify=True, request=None):
        """Refresh secret key of this profile"""

    def check_activation(self, hash, login, password):  # pylint: disable=redefined-builtin
        """Check activation for given settings"""

    def generate_reset_hash(self):
        """Create request for password reset"""

    def reset_password(self, hash, password):  # pylint: disable=redefined-builtin
        """Check password reset for given settings"""

    def to_dict(self):
        """Get main user properties as mapping"""


#
# Principals groups
#

GROUPS_FOLDER_PLUGIN_LABEL = _("Groups folder plug-in")


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
