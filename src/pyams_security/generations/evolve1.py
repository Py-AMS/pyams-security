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

__docformat__ = 'restructuredtext'

import logging

from zope.annotation import IAnnotations

from pyams_security.interfaces import IDefaultProtectionPolicy
from pyams_security.security import POLICY_ANNOTATIONS_KEY
from pyams_utils.container import find_objects_providing
from pyams_utils.registry import get_local_registry, set_local_registry


LOGGER = logging.getLogger('PyAMS (security)')

ROLES_ANNOTATIONS_KEY = 'pyams_security.roles'


def evolve(site):
    """Evolve 1: update roles annotations"""
    registry = get_local_registry()
    try:
        set_local_registry(site.getSiteManager())
        for content in find_objects_providing(site, IDefaultProtectionPolicy):
            annotations = IAnnotations(content)
            if ROLES_ANNOTATIONS_KEY in annotations:
                LOGGER.info("Updating roles annotations for {!r}".format(content))
                annotations[POLICY_ANNOTATIONS_KEY] = annotations[ROLES_ANNOTATIONS_KEY]
                del annotations[ROLES_ANNOTATIONS_KEY]
    finally:
        set_local_registry(registry)
