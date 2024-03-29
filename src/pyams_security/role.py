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

"""PyAMS_security.role module

This module provides classes related to roles definition and registration.
"""

from pyramid.exceptions import ConfigurationError
from pyramid.traversal import lineage
from zope.interface import Interface, implementer
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_layer.interfaces import IPyAMSLayer
from pyams_security.interfaces import IProtectedObject, IRoleEvent, IRolesGetter, ISecurityManager
from pyams_security.interfaces.base import IRole, ROLE_ID
from pyams_security.interfaces.names import ROLES_VOCABULARY_NAME
from pyams_utils.adapter import ContextRequestAdapter, adapter_config
from pyams_utils.registry import query_utility
from pyams_utils.request import check_request
from pyams_utils.vocabulary import vocabulary_config

__docformat__ = 'restructuredtext'


@implementer(IRole)
class Role:
    """Role utility class"""

    id = FieldProperty(IRole['id'])  # pylint: disable=invalid-name
    title = FieldProperty(IRole['title'])
    description = FieldProperty(IRole['description'])
    permissions = FieldProperty(IRole['permissions'])
    managers = FieldProperty(IRole['managers'])
    custom_data = FieldProperty(IRole['custom_data'])

    def __init__(self, values=None, **args):
        if not isinstance(values, dict):
            values = args
        self.id = values.pop('id')  # pylint: disable=invalid-name
        self.title = values.pop('title')
        self.description = values.pop('description', None)
        self.permissions = values.pop('permissions', set())
        self.managers = values.pop('managers', set())
        self.custom_data = values or {}


class RoleSelector:
    """Role based event selector predicate

    This selector can be used as a subscriber predicate to define
    a role that the event must match:

    .. code-block:: python

        from pyams_utils.interfaces.site import ISiteRoot

        @subscriber(IRoleGrantedEvent, context_selector=ISiteRoot, role_selector='myams.admin')
        def handle_granted_manager_role(event):
            '''Handle granted manager role on site root'''
    """

    def __init__(self, roles, config):  # pylint: disable=unused-argument
        if not isinstance(roles, (list, tuple, set)):
            roles = {roles}
        self.roles = roles

    def text(self):
        """Predicate text output"""
        return 'role_selector = %s' % str(self.roles)

    phash = text

    def __call__(self, event):
        assert IRoleEvent.providedBy(event)
        return event.role_id in self.roles


def register_role(config, role):
    """Register a new role

    Roles registry is not required.
    But only registered roles can be applied via default
    ZMI features.

    If a role is registered several times, previous registrations
    will just be updated to add new permissions.
    Title and description are not updated after first registration.
    """
    registry = config.registry
    if not IRole.providedBy(role):
        if isinstance(role, dict):
            role = Role(**role)
        else:
            role = Role(id=role, title=role)
    role_utility = registry.queryUtility(IRole, name=role.id)
    if role_utility is None:
        # registering a new role
        registry.registerUtility(role, IRole, name=role.id)
    else:
        # new registration of a given role to add permissions
        role_utility.permissions = (role_utility.permissions or set()) | \
                                   (role.permissions or set())
        role_utility.managers = (role_utility.managers or set()) | \
                                (role.managers or set())
        role_utility.custom_data.update(role.custom_data)


def upgrade_role(config, role, required=True, **kwargs):
    """Upgrade an existing role with new permissions or managers

    If *required* argument is True, an exception is raised if provided
    role doesn't exist.
    """
    registry = config.registry
    if not IRole.providedBy(role):
        role = registry.queryUtility(IRole, name=role)
    if role is None:
        if required:
            raise ConfigurationError("Provided role isn't registered!")
        return
    permissions = kwargs.pop('permissions', None)
    if permissions:
        role.permissions = (role.permissions or set()) | set(permissions)
    managers = kwargs.pop('managers', None)
    if managers:
        role.managers = (role.managers or set()) | set(managers)
    role.custom_data.update(kwargs)


@vocabulary_config(name=ROLES_VOCABULARY_NAME)
class RolesVocabulary(SimpleVocabulary):
    """Roles vocabulary"""

    interface = IRole

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        request = check_request()
        registry = request.registry
        translate = request.localizer.translate
        terms = [SimpleTerm(r.id, title=translate(r.title))
                 for n, r in registry.getUtilitiesFor(self.interface)]
        terms.sort(key=lambda x: x.title)
        super().__init__(terms)


@adapter_config(required=(Interface, IPyAMSLayer),
                provides=IRolesGetter)
class PrincipalRolesAdapter(ContextRequestAdapter):
    """Principal roles adapter"""

    def get_roles(self, principals):
        """Get additional roles for provided principals"""
        manager = query_utility(ISecurityManager)
        if manager is not None:
            for parent in lineage(self.context):
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    for principal in principals:
                        yield from set(map(ROLE_ID.format, protection.get_roles(principal)))
                    if not protection.inherit_parent_roles:
                        break
