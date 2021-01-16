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

"""PyAMS_security.interfaces.site module

This module defines site root roles interface.
"""

from pyams_security.interfaces import IContentRoles, SYSTEM_ADMIN_ROLE, SYSTEM_VIEWER_ROLE
from pyams_security.schema import PrincipalsSetField


__docformat__ = 'restructuredtext'

from pyams_security import _


class ISiteRootRoles(IContentRoles):
    """Site root roles"""

    managers = PrincipalsSetField(title=_("Site managers"),
                                  description=_("These principals are allowed to manage the "
                                                "whole application environment"),
                                  role_id=SYSTEM_ADMIN_ROLE,
                                  required=False)

    viewers = PrincipalsSetField(title=_("Site viewers"),
                                 description=_("These principals are allowed to view some "
                                               "application settings, without update"),
                                 role_id=SYSTEM_VIEWER_ROLE,
                                 required=False)
