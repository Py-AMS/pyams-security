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

"""PyAMS_security.property module

This module defines a custom field property used to store roles.
"""

from zope.schema.interfaces import IField, ISet

from pyams_security.interfaces import IProtectedObject, IRoleProtectedObject
from pyams_security.interfaces.base import IRole, IPrincipalInfo
from pyams_security.schema import IPrincipalBaseField


__docformat__ = 'restructuredtext'


class RolePrincipalsFieldProperty:
    """Custom field property used to handle role principals"""

    def __init__(self, field, role_id=None, name=None, **args):  # pylint: disable=unused-argument
        if not IField.providedBy(field):
            raise ValueError("Provided field must implement IField interface")
        if role_id is None:
            if not IPrincipalBaseField.providedBy(field):
                raise ValueError("Provided field must implement IRoleField interface "
                                 "or you must provide a role ID")
            role_id = field.role_id
        elif IRole.providedBy(role_id):
            role_id = role_id.id
        if role_id is None:
            raise ValueError("Can't get role ID")
        if name is None:
            name = field.__name__
        self.__field = field
        self.__name = name
        self.__role_id = role_id

    def __get__(self, instance, klass):
        if instance is None:
            return self
        protection = IProtectedObject(instance.__parent__, None)
        if protection is None:
            return set()
        return protection.get_principals(self.__role_id)

    def __set__(self, instance, value):
        field = self.__field.bind(instance)
        if ISet.providedBy(field):
            if value is None:
                value = set()
            elif isinstance(value, str):
                value = set(value.split(','))
            value = set(map(lambda x: x.id if IPrincipalInfo.providedBy(x) else x, value))
        else:
            value = value.id if IPrincipalInfo.providedBy(value) else value
        field.validate(value)
        if field.readonly:
            raise ValueError("Field {0} is readonly!".format(self.__name))
        protection = IProtectedObject(instance.__parent__, None)
        if not IRoleProtectedObject.providedBy(protection):
            raise ValueError("Can't use role properties on object not providing "
                             "IRoleProtectedObject interface!")
        # pylint: disable=assignment-from-no-return
        old_principals = protection.get_principals(self.__role_id)
        if not isinstance(value, set):
            value = {value}
        added = value - old_principals
        removed = old_principals - value
        for principal_id in added:
            protection.grant_role(self.__role_id, principal_id)
        for principal_id in removed:
            protection.revoke_role(self.__role_id, principal_id)
