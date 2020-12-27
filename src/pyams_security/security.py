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

"""PyAMS_security.security module

This module provides role-based security policy.
"""

import logging

from persistent import Persistent
from persistent.dict import PersistentDict
from pyramid.location import lineage
from pyramid.security import ALL_PERMISSIONS, Allow, Authenticated, DENY_ALL, Deny, Everyone
from zope.annotation import IAttributeAnnotatable
from zope.container.contained import Contained
from zope.interface import implementer
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import ADMIN_USER_ID, GrantedRoleEvent, IContentRoles, \
    IDefaultProtectionPolicy, IProtectedObject, IRoleProtectedObject, RevokedRoleEvent
from pyams_security.interfaces.base import IPrincipalInfo, IRole, PUBLIC_PERMISSION
from pyams_utils.adapter import adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.registry import get_pyramid_registry, query_utility
from pyams_utils.request import request_property


__docformat__ = 'restructuredtext'

LOGGER = logging.getLogger('PyAMS (security)')


@factory_config(IRoleProtectedObject)
class RoleProtectedObject(Persistent, Contained):
    """Base class for object protected by roles"""

    inherit_parent_security = FieldProperty(IRoleProtectedObject['inherit_parent_security'])
    everyone_denied = FieldProperty(IRoleProtectedObject['everyone_denied'])
    everyone_granted = FieldProperty(IRoleProtectedObject['everyone_granted'])
    authenticated_denied = FieldProperty(IRoleProtectedObject['authenticated_denied'])
    authenticated_granted = FieldProperty(IRoleProtectedObject['authenticated_granted'])
    inherit_parent_roles = FieldProperty(IRoleProtectedObject['inherit_parent_roles'])

    def __init__(self):
        self._principals_by_role = PersistentDict()
        self._roles_by_principal = PersistentDict()

    def get_everyone_denied(self):
        """Get permissions denied to everyone"""
        permissions = self.everyone_denied or set()
        if self.inherit_parent_security:
            for parent in lineage(self):
                if parent in (self, self.__parent__):
                    continue
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    permissions = permissions | (protection.everyone_denied or set())
        return permissions

    def get_everyone_granted(self):
        """Get permissions granted to everyone"""
        permissions = self.everyone_granted or set()
        if self.inherit_parent_security:
            for parent in lineage(self):
                if parent in (self, self.__parent__):
                    continue
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    permissions = permissions | (protection.everyone_granted or set())
        return permissions

    def get_authenticated_denied(self):
        """Get permissions denied to authenticated users"""
        permissions = self.authenticated_denied or set()
        if self.inherit_parent_security:
            for parent in lineage(self):
                if parent in (self, self.__parent__):
                    continue
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    permissions = permissions | (protection.authenticated_denied or set())
        return permissions

    def get_authenticated_granted(self):
        """Get permissions granted to authenticated users"""
        permissions = self.authenticated_granted or set()
        if self.inherit_parent_security:
            for parent in lineage(self):
                if parent in (self, self.__parent__):
                    continue
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    permissions = permissions | (protection.authenticated_granted or set())
        return permissions

    def grant_role(self, role_id, principal_ids):
        """Grant role to selected principals"""
        registry = get_pyramid_registry()
        if IRole.providedBy(role_id):
            role_id = role_id.id
        if isinstance(principal_ids, str):
            principal_ids = {principal_ids}
        role_principals = self._principals_by_role.get(role_id) or set()
        for principal_id in principal_ids:
            if IPrincipalInfo.providedBy(principal_id):
                principal_id = principal_id.id
            if principal_id not in role_principals:
                principal_roles = self._roles_by_principal.get(principal_id) or set()
                role_principals.add(principal_id)
                principal_roles.add(role_id)
                self._roles_by_principal[principal_id] = principal_roles
                self._principals_by_role[role_id] = role_principals
                registry.notify(GrantedRoleEvent(self, role_id, principal_id))

    def revoke_role(self, role_id, principal_ids):
        """Revoke role to selected principals"""
        registry = get_pyramid_registry()
        if IRole.providedBy(role_id):
            role_id = role_id.id
        if isinstance(principal_ids, str):
            principal_ids = {principal_ids}
        role_principals = self._principals_by_role.get(role_id) or set()
        for principal_id in principal_ids.copy():
            if IPrincipalInfo.providedBy(principal_id):
                principal_id = principal_id.id
            if principal_id in role_principals:
                principal_roles = self._roles_by_principal.get(principal_id) or set()
                if principal_id in role_principals:
                    role_principals.remove(principal_id)
                if role_id in principal_roles:
                    principal_roles.remove(role_id)
                if principal_roles:
                    self._roles_by_principal[principal_id] = principal_roles
                elif principal_id in self._roles_by_principal:
                    del self._roles_by_principal[principal_id]
                if role_principals:
                    self._principals_by_role[role_id] = role_principals
                elif role_id in self._principals_by_role:
                    del self._principals_by_role[role_id]
                registry.notify(RevokedRoleEvent(self, role_id, principal_id))

    def get_principals(self, role_id):
        """Get principals which have selected role granted"""
        if IRole.providedBy(role_id):
            role_id = role_id.id
        return self._principals_by_role.get(role_id) or set()

    def get_roles(self, principal_id):
        """Get roles for given principal"""
        if IPrincipalInfo.providedBy(principal_id):
            principal_id = principal_id.id
        return self._roles_by_principal.get(principal_id) or set()

    def get_permissions(self, principal_id):
        """Get permissions for given principal"""
        registry = get_pyramid_registry()
        result = set()
        for role_id in self.get_roles(principal_id):
            role = registry.queryUtility(IRole, role_id)
            result |= role.permissions or set()
        return result

    def get_granted_roles(self):
        """Get granted roles on current context or parents"""
        roles = set(self._principals_by_role.keys())
        if self.inherit_parent_roles:
            for parent in lineage(self):
                if parent in (self, self.__parent__):
                    continue
                protection = IProtectedObject(parent, None)
                if protection is not None:
                    roles = roles | protection.get_granted_roles()
        return roles

    @request_property(key=None)
    def __acl__(self):
        """Get ACL for current context

        The result is stored into current request annotations, so it's not supposed to change
        during request lifetime.
        """
        # always grant all permissions to system manager
        # and 'public' permission to everyone
        result = [(Allow, ADMIN_USER_ID, ALL_PERMISSIONS),
                  (Allow, Everyone, {PUBLIC_PERMISSION})]
        # grant access to all roles permissions
        for role_id in self.get_granted_roles():
            role = query_utility(IRole, role_id)
            if role is not None:
                result.append((Allow, 'role:{0}'.format(role_id), role.permissions))
        # add denied permissions to everyone and authenticated
        permissions = self.get_everyone_denied()
        if permissions:
            result.append((Deny, Everyone, permissions))
        permissions = self.get_authenticated_denied()
        if permissions:
            result.append((Deny, Authenticated, permissions))
        # add allowed permissions to everyone and authenticated
        permissions = self.get_authenticated_granted()
        if permissions:
            result.append((Allow, Authenticated, permissions))
        permissions = self.get_everyone_granted()
        if permissions:
            result.append((Allow, Everyone, permissions))
        # deny all parent permissions if inheritance is disabled
        if not self.inherit_parent_security:
            result.append(DENY_ALL)
        LOGGER.debug('ACL({0!r}) = {1}'.format(self.__parent__, str(result)))
        return result


POLICY_ANNOTATIONS_KEY = 'pyams_security.policy'


@adapter_config(required=IDefaultProtectionPolicy,
                provides=IRoleProtectedObject)
def protected_object_factory(context):
    """Default protected object factory"""
    return get_annotation_adapter(context, POLICY_ANNOTATIONS_KEY, IRoleProtectedObject)


@implementer(IAttributeAnnotatable)
class ProtectedObjectMixin:
    """Base protected object class mixin

    This mixin class is only used to automatically extract ACLs from an :py:class:`IProtectedObject
    <pyams_security.interfaces.IProtectedObject>` interface adapter.
    """

    def __acl__(self):
        protected = IProtectedObject(self, None)
        if protected is not None:
            acl = protected.__acl__()  # pylint: disable=assignment-from-no-return
            if callable(acl):
                acl = acl(protected)
            return acl
        return []


@implementer(IContentRoles)
class ProtectedObjectRoles:
    """Protected object roles base class"""

    def __init__(self, context):
        self.__parent__ = context
