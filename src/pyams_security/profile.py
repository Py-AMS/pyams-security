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

"""PyAMS_site.profile module

This module defines classes and functions to handle public profiles.
"""

from persistent import Persistent
from pyramid.interfaces import IRequest
from pyramid.security import ALL_PERMISSIONS, Allow, Everyone
from pyramid.threadlocal import get_current_request
from zope.container.contained import Contained
from zope.interface import Interface
from zope.intid.interfaces import IIntIds
from zope.location import locate
from zope.traversing.interfaces import ITraversable

from pyams_file.property import FileProperty
from pyams_security.interfaces import ADMIN_USER_ID
from pyams_security.interfaces.base import IPrincipalInfo, PUBLIC_PERMISSION
from pyams_security.interfaces.profile import IPublicProfile, PUBLIC_PROFILE_KEY
from pyams_utils.adapter import ContextRequestAdapter, adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.interfaces.tales import ITALESExtension
from pyams_utils.registry import get_utility
from pyams_utils.request import check_request, query_request


__docformat__ = 'restructuredtext'


@factory_config(IPublicProfile)
class PublicProfile(Persistent, Contained):
    """Public profile persistent class"""

    avatar = FileProperty(IPublicProfile['avatar'])

    @staticmethod
    def __acl__():
        """Default profile ACL"""
        result = [(Allow, ADMIN_USER_ID, ALL_PERMISSIONS)]
        request = query_request()
        if request is not None:
            result.append((Allow, request.principal.id, ALL_PERMISSIONS))
        result.append((Allow, Everyone, PUBLIC_PERMISSION))
        return result


@adapter_config(required=Interface, provides=IPublicProfile)
def public_profile_factory(context):  # pylint: disable=unused-argument
    """Generic public profile factory

    Applied on any context, this adapter returns public profile associated
    with the current request principal.
    """
    request = check_request()
    return IPublicProfile(request.principal)


@adapter_config(required=IRequest, provides=IPublicProfile)
def request_profile_factory(request):
    """Request public profile factory"""
    return IPublicProfile(request.principal)


@adapter_config(required=IPrincipalInfo, provides=IPublicProfile)
def principal_profile_factory(principal):
    """Principal public profile factory adapter

    Public profile is stored using IPrincipalAnnotations utility (using the
    IPrincipalInfo to IAnnotations adapter defined into :py:mod:pyams_security.principal
    module).
    """

    def public_profile_callback(profile):
        """Public profile creation callback"""
        request = get_current_request()
        if request is not None:
            root = request.root
            intids = get_utility(IIntIds)
            locate(profile, root)  # avoid NotYet exception
            locate(profile, root, '++profile++{0}'.format(intids.register(profile)))

    return get_annotation_adapter(principal, PUBLIC_PROFILE_KEY, IPublicProfile,
                                  locate=False, callback=public_profile_callback)


@adapter_config(name='profile', required=(Interface, Interface), provides=ITraversable)
class ProfileTraverser(ContextRequestAdapter):
    """++profile++ namespace traverser"""

    def traverse(self, name, furtherpath=None):  # pylint: disable=unused-argument
        """Profile traverser"""
        if not name:
            return IPublicProfile(self.request.principal)
        intids = get_utility(IIntIds)
        profile = intids.queryObject(int(name))
        return IPublicProfile(profile, None)


@adapter_config(name='public_profile', required=(Interface, Interface), provides=ITALESExtension)
class PublicProfileExtension(ContextRequestAdapter):
    """public_profile TALES extension"""

    def render(self, request=None):
        """Render TALES extension"""
        if request is None:
            request = self.request
        return IPublicProfile(request)
