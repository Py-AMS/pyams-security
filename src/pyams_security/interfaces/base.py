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

"""PyAMS_security.interfaces.base module

This module defines base security permissions and interfaces.
"""

from zope.interface import Interface
from zope.schema import Dict, Set, Text, TextLine


__docformat__ = 'restructuredtext'


FORBIDDEN_PERMISSION = 'system.forbidden'
'''Custom permission which is never granted to any user, even system manager'''

PUBLIC_PERMISSION = 'public'
'''Public permission which is granted to every principal'''

VIEW_PERMISSION = 'view'
'''View permission is a custom permission used to view contents'''

MANAGE_PERMISSION = 'manage'
'''Permission used to manage basic information; this permission is generally not used by custom
contents'''

VIEW_SYSTEM_PERMISSION = 'pyams.ViewSystem'
'''Permission used to access management screens'''

MANAGE_SYSTEM_PERMISSION = 'pyams.ManageSystem'
'''Permission used to manage system settings'''

MANAGE_SECURITY_PERMISSION = 'pyams.ManageSecurity'
'''Permission used to manage security settings'''

MANAGE_ROLES_PERMISSION = 'pyams.ManageRoles'
'''Permission used to manage roles'''


class IPermission(Interface):
    """Permission interface"""

    # pylint: disable=invalid-name
    id = TextLine(title="Unique ID",
                  required=True)

    title = TextLine(title="Title",
                     required=True)

    description = Text(title="Description",
                       required=False)


class IRole(Interface):
    """Role interface

    A role is a set of permissions; by assigning the role to a principal,
    these permissions are also granted to the principal.
    """

    # pylint: disable=invalid-name
    id = TextLine(title="Unique ID",
                  required=True)

    title = TextLine(title="Title",
                     required=True)

    description = Text(title="Description",
                       required=False)

    permissions = Set(title="Permissions",
                      description="ID of role's permissions",
                      value_type=TextLine(),
                      required=False)

    managers = Set(title="Managers",
                   description="List of principal IDs allowed to manage this role. "
                               "If it's a role, use 'role:role_id' syntax...",
                   value_type=TextLine(),
                   required=False)


class IPrincipalInfo(Interface):
    """Principal info class

    This is the generic interface of objects defined in request 'principal' attribute.
    """

    # pylint: disable=invalid-name
    id = TextLine(title="Globally unique ID",
                  required=True)

    title = TextLine(title="Principal name",
                     required=True)

    attributes = Dict(title="Principal groups",
                      description="IDs of principals to which this principal directly belongs",
                      value_type=TextLine())
