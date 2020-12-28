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
from pyramid.interfaces import IAuthenticationPolicy
from pyramid.security import Authenticated, Everyone
from zope.interface import implementer

from pyams_security.interfaces import ICredentialsPlugin, ISecurityManager
from pyams_utils.registry import get_all_utilities_registered_for, query_utility
from pyams_utils.wsgi import wsgi_environ_cache


LOGGER = logging.getLogger('PyAMS (security)')


@implementer(IAuthenticationPolicy)
class PyAMSAuthenticationPolicy:
    """PyAMS authentication policy

    This authentication policy relies on a registered ISecurityManager utility.
    Use same authentication ticket as AuthTktAuthenticationPolicy.

    See `pyramid.authentication.AuthTktAuthenticationPolicy` to get description
    of other constructor arguments.
    """

    # pylint: disable=too-many-arguments
    def __init__(self, secret,
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

    @property
    def credentials_plugins(self):
        """Get list of credentials plug-ins"""
        yield from get_all_utilities_registered_for(ICredentialsPlugin)

    @property
    def security_manager(self):
        """Get current security manager"""
        return query_utility(ISecurityManager)

    @wsgi_environ_cache('pyams_security.unauthenticated_userid', store_none=False)
    def unauthenticated_userid(self, request):
        """Get unauthenticated user ID from given request"""
        result = self.cookie.identify(request)
        if result:
            return result['userid']
        for plugin in self.credentials_plugins:
            credentials = plugin.extract_credentials(request)
            if credentials is not None:
                return credentials.id
        return None

    @wsgi_environ_cache('pyams_security.authenticated_userid', store_none=False)
    def authenticated_userid(self, request):
        """Get authenticated user ID from given request"""
        principal_id = self.unauthenticated_userid(request)
        if principal_id is None:
            return None
        try:
            manager = self.security_manager
            if manager is not None:
                return manager.authenticated_userid(request, principal_id)
        except ConnectionStateError:
            pass
        return None

    @wsgi_environ_cache('pyams_security.effective_principals')
    def effective_principals(self, request, context=None):
        """Get effective principals from given request"""
        try:
            LOGGER.debug(">>> getting principals for principal {0} ({1}) on {2!r}".format(
                request.principal.title, request.principal.id, context or request.context))
        except AttributeError:
            LOGGER.debug(">>> getting principals for request {0} on {1!r}".format(
                request, context or request.context))
        principals = {Everyone}
        principal_id = self.authenticated_userid(request)
        if principal_id:
            # get authenticated user principals
            principals.add(Authenticated)
            principals.add(principal_id)
            manager = self.security_manager
            if manager is not None:
                principals |= set(manager.effective_principals(principal_id, request, context))
        LOGGER.debug('<<< principals = {0}'.format(str(sorted(principals))))
        return principals

    def remember(self, request, principal, **kw):
        """Remember request authentication as cookie"""
        return self.cookie.remember(request, principal, **kw)

    def forget(self, request):
        """Reset authentication cookie"""
        return self.cookie.forget(request)
