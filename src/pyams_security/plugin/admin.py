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

from pyams_security.interfaces import IAdminAuthenticationPlugin, IDirectoryPlugin
from pyams_security.principal import PrincipalInfo
from pyams_utils.factory import factory_config
from pyams_utils.registry import get_utility


__docformat__ = 'restructuredtext'


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
            if value == '*****':
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
            return "{0}:{1}".format(self.prefix, login)
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
            yield PrincipalInfo(id='{0}:{1}'.format(self.prefix, self.login),
                                title=self.title)
