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

from pyams_security.interfaces import IContentRoles, SYSTEM_ADMIN_ROLE
from pyams_security.schema import PrincipalsSetField


__docformat__ = 'restructuredtext'

from pyams_security import _


class ISiteRootRoles(IContentRoles):
    """Site root roles"""

    managers = PrincipalsSetField(title=_("Site managers"),
                                  role_id=SYSTEM_ADMIN_ROLE,
                                  required=False)
