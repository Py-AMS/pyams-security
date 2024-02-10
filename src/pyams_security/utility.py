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

"""PyAMS_security.utility module

This module defines the SecurityManager utility and custom Pyramid authentication policy.
"""

import logging

from beaker.cache import cache_region
from zope.container.folder import Folder
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.plugin import IAuthenticationPlugin, \
    ICredentialsPlugin, IDirectoryPlugin, IGroupsAwareDirectoryPlugin
from pyams_security.principal import MissingPrincipal, UnknownPrincipal
from pyams_utils.factory import factory_config
from pyams_utils.registry import get_all_utilities_registered_for, get_utilities_for, \
    query_utility

__docformat__ = 'restructuredtext'

from pyams_utils.request import query_request

LOGGER = logging.getLogger('PyAMS (security)')


@factory_config(ISecurityManager)
class SecurityManager(Folder):
    """Security manager utility"""

    authentication_plugins_names = FieldProperty(ISecurityManager['authentication_plugins_names'])
    directory_plugins_names = FieldProperty(ISecurityManager['directory_plugins_names'])

    show_home_menu = FieldProperty(ISecurityManager['show_home_menu'])

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if IAuthenticationPlugin.providedBy(value):
            self.authentication_plugins_names += (key,)
        if IDirectoryPlugin.providedBy(value):
            self.directory_plugins_names += (key,)

    def __delitem__(self, key):
        super().__delitem__(key)
        if key in self.authentication_plugins_names:
            self.authentication_plugins_names = tuple(
                filter(lambda x: x != key, self.authentication_plugins_names))
        if key in self.directory_plugins_names:
            self.directory_plugins_names = tuple(
                filter(lambda x: x != key, self.directory_plugins_names))

    def get_plugin(self, name):
        """Lookup plugin for given name"""
        return query_utility(ICredentialsPlugin, name=name) or self.get(name)

    @property
    def credentials_plugins_names(self):
        """Get list of credentials plugins names"""
        yield from [name for name, plugin in get_utilities_for(ICredentialsPlugin) if name]

    @property
    def credentials_plugins(self):
        """Get list of credentials plug-ins"""
        yield from get_all_utilities_registered_for(ICredentialsPlugin)

    @property
    def authentication_plugins(self):
        """Get list of authentication plug-ins"""
        yield from get_all_utilities_registered_for(IAuthenticationPlugin)
        for name in self.authentication_plugins_names or ():
            plugin = self.get(name)
            if IAuthenticationPlugin.providedBy(plugin):
                yield plugin

    @property
    def directory_plugins(self):
        """Get list of directory plug-ins"""
        yield from get_all_utilities_registered_for(IDirectoryPlugin)
        for name in self.directory_plugins_names or ():
            plugin = self.get(name)
            if IDirectoryPlugin.providedBy(plugin):
                yield plugin

    @property
    def groups_directory_plugins(self):
        """Get list of groups plug-ins"""
        yield from get_all_utilities_registered_for(IGroupsAwareDirectoryPlugin)
        for name in self.directory_plugins_names or ():
            plugin = self.get(name)
            if IGroupsAwareDirectoryPlugin.providedBy(plugin):
                yield plugin

    # IAuthenticationInfo interface methods
    def extract_credentials(self, request, **kwargs):
        """Extract credentials from request"""
        for plugin in self.credentials_plugins:
            credentials = plugin.extract_credentials(request, **kwargs)
            if credentials:
                return credentials
        return None

    def authenticate(self, credentials, request, get_plugin_name=False, get_plugin=False):
        """Try to authenticate request with given credentials"""
        for plugin in self.authentication_plugins:
            try:
                principal_id = plugin.authenticate(credentials, request)
            except:  # pylint: disable=bare-except
                LOGGER.debug("Can't authenticate!", exc_info=True)
                continue
            else:
                if principal_id is not None:
                    if get_plugin:
                        return principal_id, plugin
                    elif get_plugin_name:
                        return principal_id, plugin.prefix
                    else:
                        return principal_id
        return (None, None) if (get_plugin or get_plugin_name) else None

    def authenticated_userid(self, request, principal_id=None):
        """Extract authenticated user ID from request"""
        if principal_id is None:
            identity = request.identity
            if identity is None:
                return None
            principal_id = identity['userid']
        if principal_id is not None:
            principal = self.get_principal(principal_id)
            if principal is not None:
                return principal.id
        return None

    @cache_region('short', 'security_plugins_principals')
    def _get_global_principals(self, principal_id):
        """Extract all principals of given principal ID"""
        principals = {principal_id}
        # get direct principals
        for plugin in self.directory_plugins:
            principals |= set(plugin.get_all_principals(principal_id))
        # get indirect principals by searching groups members
        for principal_id in principals.copy():
            for plugin in self.groups_directory_plugins:
                principals |= set(plugin.get_all_principals(principal_id))
        return principals

    def effective_principals(self, principal_id):
        """Extract effective principals of given principal ID"""
        # add principals extracted from security plug-ins
        return self._get_global_principals(principal_id)

    # IDirectoryPlugin interface methods
    @cache_region('long', 'security_plugins_principal')
    def get_principal(self, principal_id, info=True):
        """Principal lookup for given principal ID"""
        if not principal_id:
            return UnknownPrincipal
        for plugin in self.directory_plugins:
            try:
                principal = plugin.get_principal(principal_id, info)
            except:  # pylint: disable=bare-except
                LOGGER.debug("Can't get principal {0}!".format(principal_id), exc_info=True)
                continue
            else:
                if principal is not None:
                    return principal
        return MissingPrincipal(id=principal_id)

    def get_raw_principal(self, principal_id):
        """Principal lookup for given principal ID

        The method will always bypass the cache and return a *raw* principal, instead of a
        generic principal info, and None if the principal can't be found.
        """
        if not principal_id:
            return None
        for plugin in self.directory_plugins:
            try:
                principal = plugin.get_principal(principal_id, info=False)
            except:
                LOGGER.debug("Can't get principal {0}!".format(principal_id), exc_info=True)
                continue
            else:
                if principal is not None:
                    return principal
        return MissingPrincipal(id=principal_id)

    def get_all_principals(self, principal_id):
        """Get all principals of given principal ID"""
        principals = set()
        if principal_id:
            for plugin in self.directory_plugins:
                principals.update(plugin.get_all_principals(principal_id))
        return principals

    def find_principals(self, query, exact_match=False):
        """Find principals matching given query"""
        principals = set()
        for plugin in self.directory_plugins:
            try:
                principals |= set(plugin.find_principals(query, exact_match))
            except:  # pylint: disable=bare-except
                LOGGER.debug("Can't find principals!", exc_info=True)
                continue
        return sorted(principals, key=lambda x: x.title)


def get_principal(request=None, principal_id=None):
    """Get principal associated with given request"""
    assert (request is not None) or (principal_id is not None), "Request and principal ID can't be None!"
    manager = query_utility(ISecurityManager)
    if manager is None:
        return None
    if principal_id is not None:
        return manager.get_principal(principal_id)
    if request is None:
        request = query_request()
    if request is not None:
        return manager.get_principal(request.authenticated_userid)
    return UnknownPrincipal
