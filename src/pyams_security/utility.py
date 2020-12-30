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
from pyramid.location import lineage
from zope.container.folder import Folder
from zope.interface import implementer
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import AuthenticatedPrincipalEvent, IAuthenticationPlugin, \
    ICredentialsPlugin, IDirectoryPlugin, IGroupsAwareDirectoryPlugin, \
    IProtectedObject, ISecurityManager
from pyams_security.principal import MissingPrincipal, UnknownPrincipal
from pyams_utils.registry import get_all_utilities_registered_for, query_utility
from pyams_utils.request import check_request


__docformat__ = 'restructuredtext'

LOGGER = logging.getLogger('PyAMS (security)')


@implementer(ISecurityManager)
class SecurityManager(Folder):
    """Security manager utility"""

    open_registration = FieldProperty(ISecurityManager['open_registration'])
    users_folder = FieldProperty(ISecurityManager['users_folder'])

    authentication_plugins_names = FieldProperty(ISecurityManager['authentication_plugins_names'])
    directory_plugins_names = FieldProperty(ISecurityManager['directory_plugins_names'])

    def __setitem__(self, key, value):
        super(SecurityManager, self).__setitem__(key, value)
        if IAuthenticationPlugin.providedBy(value):
            self.authentication_plugins_names += (key,)
        if IDirectoryPlugin.providedBy(value):
            self.directory_plugins_names += (key,)

    def __delitem__(self, key):
        super(SecurityManager, self).__delitem__(key)
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

    def authenticate(self, credentials, request):
        """Try to authenticate request with given credentials"""
        for plugin in self.authentication_plugins:
            try:
                principal_id = plugin.authenticate(credentials, request)
            except:  # pylint: disable=bare-except
                LOGGER.debug("Can't authenticate!", exc_info=True)
                continue
            else:
                if principal_id is not None:
                    request.registry.notify(
                        AuthenticatedPrincipalEvent(plugin.prefix, principal_id))
                    return principal_id
        return None

    def authenticated_userid(self, request, principal_id=None):
        """Extract authenticated user ID from request"""
        if principal_id is None:
            credentials = self.extract_credentials(request)
            if credentials is None:
                return None
            principal_id = self.authenticate(credentials, request)
        if principal_id is not None:
            principal = self.get_principal(principal_id)
            if principal is not None:
                return principal.id
        return None

    @cache_region('short', 'security_plugins_principals')
    def _get_plugins_principals(self, principal_id):
        """Extract all principals of given principal ID"""
        principals = set()
        # get direct principals
        for plugin in self.directory_plugins:
            principals |= set(plugin.get_all_principals(principal_id))
        # get indirect principals by searching groups members
        for principal in principals.copy():
            for plugin in self.groups_directory_plugins:
                principals |= set(plugin.get_all_principals(principal))
        return principals

    def effective_principals(self, principal_id, request=None, context=None):
        """Extratc effective principals of given principal ID"""
        # add principals extracted from security plug-ins
        principals = self._get_plugins_principals(principal_id)
        # add context roles granted to principal
        if context is None:
            if request is None:
                request = check_request()
            context = request.context
        if context is not None:
            for parent in lineage(context):
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    for principal in principals.copy():
                        principals |= set(map('role:{}'.format,
                                              protection.get_roles(principal)))
                    if not protection.inherit_parent_roles:
                        break
        return principals

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


def get_principal(request, principal_id=None):
    """Get principal associated with given request"""
    manager = query_utility(ISecurityManager)
    if manager is not None:
        if principal_id is None:
            principal_id = request.authenticated_userid
        if principal_id:
            return manager.get_principal(principal_id)
        return UnknownPrincipal
    return None
