#
# Copyright (c) 2008-2015 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.plugin.admin module

This module defines system principals which are used for system management tasks and for
internal services.
"""

from os import urandom

from persistent import Persistent
from zope.container.contained import Contained
from zope.interface import implementer
from zope.password.interfaces import IPasswordManager
from zope.schema.fieldproperty import FieldProperty

from pyams_security.credential import Credentials
from pyams_security.interfaces.names import INTERNAL_USER_ID, PRINCIPAL_ID_FORMATTER, UNCHANGED_PASSWORD
from pyams_security.interfaces.plugin import IAdminAuthenticationPlugin, ICredentialsPlugin, IDirectoryPlugin
from pyams_security.principal import PrincipalInfo
from pyams_utils.factory import factory_config
from pyams_utils.registry import get_utility, utility_config
from pyams_utils.wsgi import wsgi_environ_cache

__docformat__ = 'restructuredtext'

from pyams_security import _


@factory_config(IAdminAuthenticationPlugin)
@implementer(IDirectoryPlugin)
class AdminAuthenticationPlugin(Persistent, Contained):
    """Hard-coded administrator authenticator plug-in

    This plug-in should only be enabled in development mode!!!
    """

    prefix = FieldProperty(IAdminAuthenticationPlugin['prefix'])
    title = FieldProperty(IAdminAuthenticationPlugin['title'])
    enabled = FieldProperty(IAdminAuthenticationPlugin['enabled'])

    login = FieldProperty(IAdminAuthenticationPlugin['login'])
    _password = FieldProperty(IAdminAuthenticationPlugin['password'])
    _password_salt = None

    @property
    def password(self):
        """Get current password"""
        return self._password

    @password.setter
    def password(self, value):
        """Encode password before storing new value"""
        if value:
            if value == UNCHANGED_PASSWORD:
                return
            self._password_salt = urandom(4)
            manager = get_utility(IPasswordManager, name='SSHA')
            self._password = manager.encodePassword(value, salt=self._password_salt)
        else:
            self._password = None

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Try to authenticate principal using given credentials"""
        if not (self.enabled and self.password):
            return None
        attrs = credentials.attributes
        login = attrs.get('login')
        password = attrs.get('password')
        manager = get_utility(IPasswordManager, name='SSHA')
        if login == self.login and manager.checkPassword(self.password, password):
            return PRINCIPAL_ID_FORMATTER.format(prefix=self.prefix,
                                                 login=login)
        return None

    def get_principal(self, principal_id, info=True):
        """Get principal matching given principal ID"""
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, login = principal_id.split(':', 1)
        if (prefix == self.prefix) and (login == self.login):
            if info:
                return PrincipalInfo(id=principal_id,
                                     title=self.title)
            return self
        return None

    def get_all_principals(self, principal_id):
        """Get all principals matching given principal ID"""
        if not self.enabled:
            return set()
        if self.get_principal(principal_id) is not None:
            return {principal_id}
        return set()

    def find_principals(self, query, exact_match=False):
        """Search principals matching given query"""
        if not query:
            return
        query = query.lower()
        title = self.title.lower()
        if (query == self.login) or (not exact_match and query in title):
            yield PrincipalInfo(id=PRINCIPAL_ID_FORMATTER.format(prefix=self.prefix,
                                                                 login=self.login),
                                title=self.title)


INTERNAL_CREDENTIALS_ENVKEY = "pyams_security.credentials.internal"


@utility_config(name='internal-auth',
                provides=ICredentialsPlugin)
class InternalUserCredentialsPlugin:
    """Internal user credentials plug-in"""
    
    prefix = 'internal'
    title = _("Internal request authentication")
    enabled = True
    
    @wsgi_environ_cache(INTERNAL_CREDENTIALS_ENVKEY, store_none=False)
    def extract_credentials(self, request, **kwargs):  # pylint: disable-unused-argument
        principal_id = getattr(request, 'principal_id', None)
        if principal_id == INTERNAL_USER_ID:
            return Credentials(self.prefix, principal_id,
                               pre_authenticated=True)
        return None
