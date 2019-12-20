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

"""PyAMS_security.index module

"""

from hypatia.keyword import KeywordIndex

from pyams_security.interfaces import IProtectedObject


__docformat__ = 'restructuredtext'


class PrincipalsRoleIndex(KeywordIndex):
    """Principals role index"""

    def __init__(self, role_id, family=None):
        KeywordIndex.__init__(self, role_id, family)
        self.role_id = role_id

    def discriminate(self, obj, default):
        protected_object = IProtectedObject(obj, None)
        if protected_object is None:
            return default
        return protected_object.get_principals(self.role_id)
