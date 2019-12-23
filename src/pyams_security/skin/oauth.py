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

"""PyAMS_security.skin.oauth module

This module provides a login view for OAuth authentication.
Please note that this login method requires additional components provided by PyAMS_security_skin
package.
"""

from logging import WARNING

from authomatic import Authomatic
from authomatic.adapters import WebObAdapter
from pyramid.httpexceptions import HTTPNotFound
from pyramid.response import Response
from pyramid.security import remember
from pyramid.view import view_config

from pyams_security.interfaces import AuthenticatedPrincipalEvent, IOAuthLoginConfiguration, \
    ISecurityManager, LOGIN_REFERER_KEY
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'


@view_config(route_name='oauth_login')
def login(request):
    """Login view for Authomatic authentication"""
    # check security manager utility
    manager = query_utility(ISecurityManager)
    if (manager is None) or not manager.enable_oauth_login:
        raise HTTPNotFound()
    # store referrer
    session = request.session
    if LOGIN_REFERER_KEY not in session:
        session[LOGIN_REFERER_KEY] = request.referer
    # init authomatic
    provider_name = request.matchdict.get('provider_name')
    # pylint: disable=assignment-from-no-return
    configuration = IOAuthLoginConfiguration(manager).get_oauth_configuration()
    authomatic = Authomatic(config=configuration, secret=manager.authomatic_secret,
                            logging_level=WARNING)
    # perform login
    response = Response()
    result = authomatic.login(WebObAdapter(request, response), provider_name)
    if result:
        if result.error:
            pass
        elif result.user:
            if not (result.user.id and result.user.name):
                result.user.update()
            oauth_folder = manager.get(manager.oauth_users_folder)
            user_id = '{provider_name}.{user_id}'.format(provider_name=provider_name,
                                                         user_id=result.user.id)
            request.registry.notify(AuthenticatedPrincipalEvent(plugin='oauth',
                                                                principal_id=user_id,
                                                                provider_name=provider_name,
                                                                user=result.user))
            principal_id = '{prefix}:{user_id}'.format(prefix=oauth_folder.prefix,
                                                       user_id=user_id)
            headers = remember(request, principal_id)
            response.headerlist.extend(headers)
        if manager.oauth_login_use_popup:
            response.text = result.popup_html()
        response.status_code = 302
        if LOGIN_REFERER_KEY in session:
            response.location = session[LOGIN_REFERER_KEY]
            del session[LOGIN_REFERER_KEY]
        else:
            response.location = '/'
    return response
