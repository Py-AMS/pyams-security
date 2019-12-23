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

"""PyAMS_security.schema module

This module contains security-related schema fields.
"""

from zope.interface import Interface, implementer
from zope.schema import Choice, Set, TextLine
from zope.schema.interfaces import IChoice, ISet, ITextLine

from pyams_security.interfaces.base import IPermission, IRole, IPrincipalInfo
from pyams_security.interfaces.names import PERMISSIONS_VOCABULARY_NAME, ROLES_VOCABULARY_NAME


__docformat__ = 'restructuredtext'


class IPermissionField(IChoice):
    """Permission field interface"""


@implementer(IPermissionField)
class PermissionField(Choice):
    """Permission field"""

    def __init__(self, **kwargs):
        if 'vocabulary' in kwargs:
            del kwargs['vocabulary']
        super(PermissionField, self).__init__(vocabulary=PERMISSIONS_VOCABULARY_NAME, **kwargs)

    def validate(self, value):
        if IPermission.providedBy(value):
            value = value.id
        super(PermissionField, self).validate(value)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if IPermission.providedBy(value):
            value = value.id
        super(PermissionField, self).set(object, value)


class IPermissionsSetField(ISet):
    """Permissions set field interface"""


def get_permission_id(value):
    """Get permission ID"""
    return value.id if IPermission.providedBy(value) else value


@implementer(IPermissionsSetField)
class PermissionsSetField(Set):
    """Permissions set field"""

    value_type = PermissionField()

    def __init__(self, **kwargs):
        if 'value_type' in kwargs:
            del kwargs['value_type']
        super(PermissionsSetField, self).__init__(value_type=PermissionField(), **kwargs)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if value:
            value = set(map(get_permission_id, value))
        super(PermissionsSetField, self).set(object, value)


class IRoleField(IChoice):
    """Role field interface"""


@implementer(IRoleField)
class RoleField(Choice):
    """Role field"""

    def __init__(self, **kwargs):
        if 'vocabulary' in kwargs:
            del kwargs['vocabulary']
        super(RoleField, self).__init__(vocabulary=ROLES_VOCABULARY_NAME, **kwargs)

    def validate(self, value):
        if IRole.providedBy(value):
            value = value.id
        super(RoleField, self).validate(value)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if IRole.providedBy(value):
            value = value.id
        super(RoleField, self).set(object, value)


class IRolesSetField(ISet):
    """Roles set field interface"""


def get_role_id(value):
    """Get role ID"""
    return value.id if IRole.providedBy(value) else value


@implementer(IRolesSetField)
class RolesSetField(Set):
    """Roles set field"""

    value_type = RoleField()

    def __init__(self, **kwargs):
        if 'value_type' in kwargs:
            del kwargs['value_type']
        super(RolesSetField, self).__init__(value_type=RoleField(), **kwargs)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if value:
            value = set(map(get_role_id, value))
        super(RolesSetField, self).set(object, value)


class IPrincipalBaseField(Interface):
    """Base role field interface"""

    role_id = TextLine(title="Matching role ID",
                       required=False)


class IPrincipalField(ITextLine, IPrincipalBaseField):
    """Principal field interface"""


@implementer(IPrincipalField)
class PrincipalField(TextLine):
    """Principal field"""

    role_id = None

    def __init__(self, **kwargs):
        if 'role_id' in kwargs:
            self.role_id = kwargs.pop('role_id')
        super(PrincipalField, self).__init__(**kwargs)

    def validate(self, value):
        if IPrincipalInfo.providedBy(value):
            value = value.id
        super(PrincipalField, self).validate(value)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if IPrincipalInfo.providedBy(value):
            value = value.id
        super(PrincipalField, self).set(object, value)


class IPrincipalsSetField(ISet, IPrincipalBaseField):
    """Principals set interface"""


def get_principal_id(value):
    """Get principal ID"""
    return value.id if IPrincipalInfo.providedBy(value) else value


@implementer(IPrincipalsSetField)
class PrincipalsSetField(Set):
    """Principals set field"""

    role_id = None
    value_type = PrincipalField()

    def __init__(self, **kwargs):
        if 'role_id' in kwargs:
            self.role_id = kwargs.pop('role_id')
        super(PrincipalsSetField, self).__init__(**kwargs)

    def set(self, object, value):  # pylint: disable=redefined-builtin
        if value:
            value = set(map(get_principal_id, value))
        super(PrincipalsSetField, self).set(object, value)
