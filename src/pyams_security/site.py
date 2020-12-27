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

"""PyAMS_security.site module

This module defines standard system manager role supported by site's root.
"""

__docformat__ = 'restructuredtext'

from zope.interface import implementer

from pyams_security.interfaces import IRolesPolicy, SYSTEM_ADMIN_ROLE
from pyams_security.interfaces.site import ISiteRootRoles
from pyams_security.property import RolePrincipalsFieldProperty
from pyams_security.security import ProtectedObjectRoles
from pyams_site.interfaces import ISiteRoot
from pyams_utils.adapter import ContextAdapter, adapter_config


@implementer(ISiteRootRoles)
class SiteRootRoles(ProtectedObjectRoles):
    """Site root roles"""

    managers = RolePrincipalsFieldProperty(ISiteRootRoles['managers'])


@adapter_config(required=ISiteRoot,
                provides=ISiteRootRoles)
def site_root_roles_adapter(context):
    """Site root roles adapter"""
    return SiteRootRoles(context)


@adapter_config(name=SYSTEM_ADMIN_ROLE,
                required=ISiteRoot,
                provides=IRolesPolicy)
class SiteRootRolesPolicy(ContextAdapter):
    """Site root roles policy"""

    roles_interface = ISiteRootRoles
    weight = 1
