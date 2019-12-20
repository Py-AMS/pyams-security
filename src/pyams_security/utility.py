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

"""

import logging
from functools import lru_cache

from beaker.cache import cache_region
from pyramid.authentication import AuthTktCookieHelper
from pyramid.decorator import reify
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.location import lineage
from pyramid.security import Authenticated, Everyone
from zope.container.folder import Folder
from zope.interface import implementer
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import AuthenticatedPrincipalEvent, IAuthenticationPlugin, \
    ICredentialsPlugin, IDirectoryPlugin, IGroupsAwareDirectoryPlugin, IProtectedObject, \
    ISecurityManager
from pyams_security.principal import MissingPrincipal, UnknownPrincipal
from pyams_utils.registry import query_utility
from pyams_utils.request import check_request, request_property
from pyams_utils.wsgi import wsgi_environ_cache


__docformat__ = 'restructuredtext'

LOGGER = logging.getLogger('PyAMS (security)')


@implementer(ISecurityManager)
class SecurityManager(Folder):
    """Security manager utility"""

    enable_social_login = FieldProperty(ISecurityManager['enable_social_login'])
    social_users_folder = FieldProperty(ISecurityManager['social_users_folder'])
    authomatic_secret = FieldProperty(ISecurityManager['authomatic_secret'])
    social_login_use_popup = FieldProperty(ISecurityManager['social_login_use_popup'])
    open_registration = FieldProperty(ISecurityManager['open_registration'])
    users_folder = FieldProperty(ISecurityManager['users_folder'])

    authentication_plugins_names = FieldProperty(ISecurityManager['authentication_plugins_names'])
    directory_plugins_names = FieldProperty(ISecurityManager['directory_plugins_names'])

    @property
    def credentials_plugins_names(self):
        request = check_request()
        policy = request.registry.queryUtility(IAuthenticationPolicy)
        return policy.credentials_names

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
        if name in self.credentials_plugins_names:
            return query_utility(ICredentialsPlugin, name=name)
        elif name:
            return self.get(name)

    def get_credentials_plugins(self, request=None):
        if request is None:
            request = check_request()
        policy = request.registry.queryUtility(IAuthenticationPolicy)
        for plugin in policy.credentials_plugins:
            if plugin is not None:
                yield plugin

    def get_authentication_plugins(self):
        for name in self.authentication_plugins_names or ():
            plugin = self.get(name)
            if IAuthenticationPlugin.providedBy(plugin):
                yield plugin

    def get_directory_plugins(self):
        for name in self.directory_plugins_names or ():
            plugin = self.get(name)
            if IDirectoryPlugin.providedBy(plugin):
                yield plugin

    def get_groups_directory_plugins(self):
        for name in self.directory_plugins_names or ():
            plugin = self.get(name)
            if IGroupsAwareDirectoryPlugin.providedBy(plugin):
                yield plugin

    # IAuthenticationInfo interface methods
    def extract_credentials(self, request, **kwargs):
        for plugin in self.get_credentials_plugins():
            credentials = plugin.extract_credentials(request, **kwargs)
            if credentials:
                return credentials

    def authenticate(self, credentials, request):
        for plugin in self.get_authentication_plugins():
            try:
                principal_id = plugin.authenticate(credentials, request)
            except:
                LOGGER.debug("Can't authenticate!", exc_info=True)
                continue
            else:
                if principal_id is not None:
                    request.registry.notify(
                        AuthenticatedPrincipalEvent(plugin.prefix, principal_id))
                    return principal_id

    def authenticated_userid(self, request):
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
        principals = set()
        # get direct principals
        for plugin in self.get_directory_plugins():
            principals |= set(plugin.get_all_principals(principal_id))
        # get indirect principals by searching groups members
        for principal in principals.copy():
            for plugin in self.get_groups_directory_plugins():
                principals |= set(plugin.get_all_principals(principal))
        return principals

    def effective_principals(self, principal_id, request=None, context=None):
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
                    for principal_id in principals.copy():
                        principals |= set(map(lambda x: 'role:{0}'.format(x),
                                              protection.get_roles(principal_id)))
                    if not protection.inherit_parent_roles:
                        break
        return principals

    # IDirectoryPlugin interface methods
    @lru_cache(maxsize=100)
    def get_principal(self, principal_id, info=True):
        if not principal_id:
            return UnknownPrincipal
        for plugin in self.get_directory_plugins():
            try:
                principal = plugin.get_principal(principal_id, info)
            except:
                LOGGER.debug("Can't get principal {0}!".format(principal_id), exc_info=True)
                continue
            else:
                if principal is not None:
                    return principal
        return MissingPrincipal(id=principal_id)

    def get_all_principals(self, principal_id):
        principals = set()
        if principal_id:
            for plugin in self.get_directory_plugins():
                principals.update(plugin.get_all_principals(principal_id))
        return principals

    def find_principals(self, query):
        principals = set()
        for plugin in self.get_directory_plugins():
            try:
                principals |= set(plugin.find_principals(query))
            except:
                LOGGER.debug("Can't find principals!", exc_info=True)
                continue
        return sorted(principals, key=lambda x: x.title)


@implementer(IAuthenticationPolicy)
class PyAMSAuthenticationPolicy:
    """PyAMS authentication policy

    This authentication policy relies on a registered ISecurityManager utility.
    Use same authentication ticket as AuthTktAuthenticationPolicy.

    ``credentials`` is the list of credentials extraction utilities which can be
    used to get credentials.

    See `pyramid.authentication.AuthTktAuthenticationPolicy` to get description
    of other constructor arguments.
    """

    def __init__(self, secret,
                 credentials=('http',),
                 cookie_name='auth_ticket',
                 secure=False,
                 include_ip=False,
                 timeout=None,
                 reissue_time=None,
                 max_age=None,
                 path="/",
                 http_only=False,
                 wild_domain=True,
                 hashalg='sha256',
                 parent_domain=False,
                 domain=None):
        self.credentials_names = credentials
        self.cookie = AuthTktCookieHelper(secret,
                                          cookie_name=cookie_name,
                                          secure=secure,
                                          include_ip=include_ip,
                                          timeout=timeout,
                                          reissue_time=reissue_time,
                                          max_age=max_age,
                                          http_only=http_only,
                                          path=path,
                                          wild_domain=wild_domain,
                                          hashalg=hashalg,
                                          parent_domain=parent_domain,
                                          domain=domain)

    @reify
    def credentials_plugins(self):
        return [query_utility(ICredentialsPlugin, name=name)
                for name in self.credentials_names]

    def _get_security_manager(self, request):
        return query_utility(ISecurityManager)

    @wsgi_environ_cache('pyams_security.unauthenticated_userid')
    def unauthenticated_userid(self, request):
        result = self.cookie.identify(request)
        if result:
            return result['userid']
        for plugin in self.credentials_plugins:
            if plugin is not None:
                credentials = plugin.extract_credentials(request)
                if credentials is not None:
                    return credentials.id

    @wsgi_environ_cache('pyams_security.authenticated_userid')
    def authenticated_userid(self, request):
        principal_id = self.unauthenticated_userid(request)
        if principal_id:
            return principal_id
        manager = self._get_security_manager(request)
        if manager is not None:
            return manager.authenticated_userid(request)

    @request_property(key=None)
    def effective_principals(self, request, context=None):
        try:
            LOGGER.debug(">>> getting principals for principal {0} ({1}) on {2!r}".format(
                request.principal.title,
                request.principal.id,
                context or request.context))
        except AttributeError:
            LOGGER.debug(">>> getting principals for request {0} on {1!r}".format(request,
                                                                                  context or request.context))
        principals = {Everyone}
        principal_id = self.unauthenticated_userid(request)
        if principal_id:
            # get authenticated user principals
            principals.add(Authenticated)
            principals.add(principal_id)
            manager = self._get_security_manager(request)
            if manager is not None:
                principals |= set(manager.effective_principals(principal_id, request, context))
        LOGGER.debug('<<< principals = {0}'.format(str(sorted(principals))))
        return principals

    def remember(self, request, principal, **kw):
        return self.cookie.remember(request, principal, **kw)

    def forget(self, request):
        return self.cookie.forget(request)


def get_principal(request, principal_id=None):
    """Get principal associated with given request"""
    manager = query_utility(ISecurityManager)
    if manager is not None:
        if principal_id is None:
            principal_id = request.authenticated_userid
        if principal_id:
            return manager.get_principal(principal_id)
        else:
            return UnknownPrincipal
