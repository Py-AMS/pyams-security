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

"""PyAMS_security.skin main module

This module provides principals search function.
"""

from pyramid.view import view_config

from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import VIEW_SYSTEM_PERMISSION
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'


@view_config(name='find-principals.json', permission=VIEW_SYSTEM_PERMISSION,
             renderer='json', xhr=True)
def find_principals(request):
    """Find all principals matching given query"""
    query = request.params.get('query')
    if not query:
        return []
    manager = query_utility(ISecurityManager)
    return [{
        'id': principal.id,
        'text': principal.title
    } for principal in manager.find_principals(query, exact_match=False)]
