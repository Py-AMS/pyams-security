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

"""PyAMS_security.plugin.group module

This module defines local groups of principals.
"""

import logging

from BTrees import OOBTree  # pylint: disable=no-name-in-module
from persistent import Persistent
from pyramid.events import subscriber
from zope.container.contained import Contained
from zope.container.folder import Folder
from zope.lifecycleevent.interfaces import IObjectAddedEvent
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_security.interfaces import IGroupsFolderPlugin, ILocalGroup, \
    IPrincipalsAddedToGroupEvent, IPrincipalsRemovedFromGroupEvent, ISecurityManager, \
    PrincipalsAddedToGroupEvent, PrincipalsRemovedFromGroupEvent
from pyams_security.interfaces.names import LOCAL_GROUPS_VOCABULARY_NAME
from pyams_security.principal import PrincipalInfo
from pyams_utils.factory import factory_config
from pyams_utils.registry import query_utility
from pyams_utils.request import check_request
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'

LOGGER = logging.getLogger('PyAMS(security)')

GROUP_ID_FORMATTER = '{prefix}:{group_id}'


@factory_config(ILocalGroup)
class Group(Persistent, Contained):
    """Local group persistent class"""

    group_id = FieldProperty(ILocalGroup['group_id'])
    title = FieldProperty(ILocalGroup['title'])
    description = FieldProperty(ILocalGroup['description'])

    _principals = FieldProperty(ILocalGroup['principals'])

    @property
    def principals(self):
        """Get principals list"""
        return self._principals or set()

    @principals.setter
    def principals(self, value):
        if not value:
            value = set()
        added = value - self._principals
        removed = self._principals - value
        if added or removed:
            self._principals = value
            registry = check_request().registry
            if added:
                LOGGER.debug("Added principals {0} to group {1} ({2})".format(
                    str(added), self.group_id, self.title))
                registry.notify(PrincipalsAddedToGroupEvent(self, added))
            if removed:
                LOGGER.debug("Removed principals {0} from group {1} ({2})".format(
                    str(removed), self.group_id, self.title))
                registry.notify(PrincipalsRemovedFromGroupEvent(self, removed))


@vocabulary_config(name=LOCAL_GROUPS_VOCABULARY_NAME)
class LocalGroupsVocabulary(SimpleVocabulary):
    """'PyAMS local groups vocabulary"""

    def __init__(self, context=None):  # pylint: disable=unused-argument
        terms = []
        manager = query_utility(ISecurityManager)
        if manager is not None:
            for plugin in manager.values():
                if IGroupsFolderPlugin.providedBy(plugin):
                    for group in plugin.values():
                        terms.append(SimpleTerm('{prefix}:{group_id}'.format(
                            prefix=plugin.prefix, group_id=group.group_id),
                                                title=group.title))
        super(LocalGroupsVocabulary, self).__init__(terms)


@factory_config(IGroupsFolderPlugin)
class GroupsFolder(Folder):
    """Principals groups folder"""

    prefix = FieldProperty(IGroupsFolderPlugin['prefix'])
    title = FieldProperty(IGroupsFolderPlugin['title'])
    enabled = FieldProperty(IGroupsFolderPlugin['enabled'])

    def __init__(self):
        super(GroupsFolder, self).__init__()
        self.groups_by_principal = OOBTree.OOBTree()  # pylint: disable=no-member

    def check_group_id(self, group_id):
        """Check for existence of given group ID"""
        if not group_id:
            return False
        return group_id not in self

    def get_principal(self, principal_id, info=True):
        """Principal lookup for given principal ID"""
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, group_id = principal_id.split(':', 1)  # pylint: disable=unused-variable
        group = self.get(group_id)
        if group is not None:
            if info:
                return PrincipalInfo(id=GROUP_ID_FORMATTER.format(prefix=self.prefix,
                                                                  group_id=group.group_id),
                                     title=group.title)
            return group
        return None

    def get_all_principals(self, principal_id, seen=None):
        """Get all principals matching given principal ID"""
        if not self.enabled:
            return set()
        principals = self.groups_by_principal.get(principal_id) or set()
        principals = principals.copy()
        if principals:
            if seen is None:
                seen = set()
            for principal in (p for p in principals.copy() if p not in seen):
                seen.add(principal)
                if principal.startswith(self.prefix + ':'):
                    principals.update(self.get_all_principals(principal, seen))
        return principals

    def find_principals(self, query, exact_match=False):
        """Find principals matching given query"""
        if not self.enabled:
            return
        if not query:
            return
        query = query.lower()
        for group in self.values():
            title = group.title
            if not title:
                continue
            title = title.lower()
            if (query == title) or (not exact_match and query in title):
                yield PrincipalInfo(id=GROUP_ID_FORMATTER.format(prefix=self.prefix,
                                                                 group_id=group.group_id),
                                    title=group.title)


@subscriber(IObjectAddedEvent, context_selector=ILocalGroup)
def handle_added_group(event):
    """Handle added group"""
    group = event.object
    folder = event.newParent
    principals_map = folder.groups_by_principal
    for principal_id in group.principals:
        groups_set = principals_map.get(principal_id)
        if groups_set is None:
            groups_set = set()
        group_id = GROUP_ID_FORMATTER.format(prefix=folder.prefix,
                                             group_id=group.group_id)
        groups_set.add(group_id)
        principals_map[principal_id] = groups_set


@subscriber(IPrincipalsAddedToGroupEvent)
def handle_added_principals(event):
    """Handle principals added to group"""
    group = event.group
    if group.__parent__ is None:  # can occur when a group is created
        return
    principals_map = group.__parent__.groups_by_principal
    for principal_id in event.principals:
        groups_set = principals_map.get(principal_id)
        if groups_set is None:
            groups_set = set()
        group_id = GROUP_ID_FORMATTER.format(prefix=group.__parent__.prefix,
                                             group_id=group.group_id)
        groups_set.add(group_id)
        principals_map[principal_id] = groups_set


@subscriber(IPrincipalsRemovedFromGroupEvent)
def handle_removed_principals(event):
    """Handle principals removed from group"""
    group = event.group
    principals_map = group.__parent__.groups_by_principal
    for principal_id in event.principals:
        groups_set = principals_map.get(principal_id)
        if groups_set:
            group_id = GROUP_ID_FORMATTER.format(prefix=group.__parent__.prefix,
                                                 group_id=group.group_id)
            if group_id in groups_set:
                groups_set.remove(group_id)
            if groups_set:
                principals_map[principal_id] = groups_set
            else:
                del principals_map[principal_id]
