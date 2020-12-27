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

"""PyAMS_security.permission module

This module provides classes related to permissions definition and registration.
"""

from zope.interface import implementer
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_security.interfaces import IViewContextPermissionChecker
from pyams_security.interfaces.base import IPermission
from pyams_security.interfaces.names import PERMISSIONS_VOCABULARY_NAME
from pyams_utils.request import check_request
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'


@implementer(IPermission)
class Permission:
    """Permission utility class"""

    id = FieldProperty(IPermission['id'])  # pylint: disable=invalid-name
    title = FieldProperty(IPermission['title'])
    description = FieldProperty(IPermission['description'])

    def __init__(self, values=None, **args):  # pylint: disable=unused-argument
        if not isinstance(values, dict):
            values = args
        self.id = values.get('id')  # pylint: disable=invalid-name
        self.title = values.get('title')
        self.description = values.get('description')


def register_permission(config, permission):
    """Register a new permission

    Permissions registry is not required.
    But only registered permissions can be applied via default
    ZMI features
    """
    if not IPermission.providedBy(permission):
        if isinstance(permission, dict):
            permission = Permission(id=permission.get('id'),
                                    title=permission.get('title'))
        else:
            permission = Permission(id=permission, title=permission)
    config.registry.registerUtility(permission, IPermission, name=permission.id)


@vocabulary_config(name=PERMISSIONS_VOCABULARY_NAME)
class PermissionsVocabulary(SimpleVocabulary):
    """Permissions vocabulary"""

    interface = IPermission

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        request = check_request()
        registry = request.registry
        translate = request.localizer.translate
        terms = [SimpleTerm(p.id, title=translate(p.title))
                 for n, p in registry.getUtilitiesFor(self.interface)]
        terms.sort(key=lambda x: x.title)
        super(PermissionsVocabulary, self).__init__(terms)


def get_edit_permission(request, context=None, view=None):
    """Get required edit permission"""
    if context is None:
        context = request.context
    registry = request.registry
    checker = registry.queryMultiAdapter((context, request, view), IViewContextPermissionChecker)
    if checker is None:
        checker = registry.queryAdapter(context, IViewContextPermissionChecker)
    if checker is not None:
        return checker.edit_permission
    return None
