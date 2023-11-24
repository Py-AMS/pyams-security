#
# Copyright (c) 2015-2020 Thierry Florac <tflorac AT ulthar.net>
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

__docformat__ = 'restructuredtext'

import logging

from ZODB.POSException import ConnectionStateError
from pyramid.authentication import AuthTktCookieHelper
from pyramid.authorization import ACLHelper, Authenticated, Everyone
from pyramid.interfaces import ISecurityPolicy
from pyramid.request import RequestLocalCache
from zope.interface import implementer

from pyams_security.interfaces import IPrincipalsGetter, IRolesGetter, ISecurityManager
from pyams_security.interfaces.base import IPrincipalInfo
from pyams_security.interfaces.plugin import ICredentialsPlugin
from pyams_utils.adapter import get_adapter_weight
from pyams_utils.dict import DotDict
from pyams_utils.registry import get_all_utilities_registered_for, query_utility
from pyams_utils.wsgi import wsgi_environ_cache

LOGGER = logging.getLogger('PyAMS (security)')


@implementer(ISecurityPolicy)
class PyAMSSecurityPolicy:
    """PyAMS security policy"""

    debug = False

    def __init__(self,
                 secret,
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
                 domain=None,
                 samesite='Lax',
                 debug=False):
        self.cookie_helper = AuthTktCookieHelper(secret,
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
                                                 domain=domain,
                                                 samesite=samesite)
        self.identity_cache = RequestLocalCache(self.get_identity)
        self.debug = debug

    @property
    def credentials_plugins(self):
        """Get list of credentials plug-ins"""
        yield from get_all_utilities_registered_for(ICredentialsPlugin)

    @property
    def security_manager(self):
        """Get current security manager"""
        return query_utility(ISecurityManager)

    def get_identity(self, request, context=None):
        """Get request identity"""
        sm = self.security_manager
        if sm is None:
            return None
        if context is None:
            context = request.context
        principals = {Everyone}
        principal_id = None
        identity = self.cookie_helper.identify(request)
        if identity is not None:
            principal_id = identity['userid']
        else:
            for plugin in self.credentials_plugins:
                credentials = plugin.extract_credentials(request)
                if (credentials is not None) and (sm is not None):
                    principal_id = sm.authenticate(credentials, request)
                    if IPrincipalInfo.providedBy(principal_id):
                        principal_id = principal_id.id
                    if principal_id is not None:
                        identity = {
                            'userid': principal_id
                        }
                        break
        if principal_id:
            principals.add(Authenticated)
            principals.add(principal_id)
            principals |= sm.effective_principals(principal_id)
            for name, adapter in request.registry.getAdapters((context, request), IPrincipalsGetter):
                principals |= set(adapter.get_principals(principal_id) or ())
            for name, adapter in request.registry.getAdapters((context, request), IRolesGetter):
                principals |= set(adapter.get_roles(principals) or ())
            identity['principals'] = principals
        return DotDict(identity) if identity is not None else None

    def identity(self, request):
        """Return identity of the current user"""
        return self.identity_cache.get_or_create(request)

    @wsgi_environ_cache('pyams_security.authenticated_userid', store_none=False)
    def authenticated_userid(self, request):
        """Get authenticated user ID from given request"""
        identity = request.identity
        if identity is None:
            return None
        try:
            manager = self.security_manager
            if manager is not None:
                return manager.authenticated_userid(request, identity['userid'])
        except ConnectionStateError:
            pass
        return None

    def permits(self, request, context, permission):
        """Return an instance of :class:`pyramid.security.Allowed` if a user
        of the given identity is allowed the ``permission`` in the current
        ``context``, else return an instance of :class:`pyramid.security.Denied`.
        """
        if self.debug:
            try:
                LOGGER.debug(f">>> getting permissions for principal {request.principal.title} "
                             f"({request.principal.id}) on {context if context is not None else request.context!r}")
            except AttributeError:
                LOGGER.debug(f">>> getting permissions for request {request} on "
                             f"{context if context is not None else request.context!r}")
        principals = {Everyone}
        identity = request.identity if context is request.context else self.get_identity(request, context)
        if identity is not None:
            principals = identity['principals']
            if self.debug:
                LOGGER.debug(f'  < principals = {principals}')
        permissions = ACLHelper().permits(context, principals, permission)
        if self.debug:
            LOGGER.debug(f'<<< permissions = {permissions}')
        return permissions

    def remember(self, request, principal, **kw):
        """Remember request authentication as cookie"""
        return self.cookie_helper.remember(request, principal, **kw)

    def forget(self, request):
        """Reset authentication cookie"""
        return self.cookie_helper.forget(request)
