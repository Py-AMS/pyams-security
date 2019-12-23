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

"""PyAMS_security.credential module

This module defines credentials class.
"""

from zope.interface import implementer
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import ICredentials


__docformat__ = 'restructuredtext'


@implementer(ICredentials)
class Credentials:
    """Credentials class"""

    prefix = FieldProperty(ICredentials['prefix'])
    id = FieldProperty(ICredentials['id'])  # pylint: disable=invalid-name
    attributes = FieldProperty(ICredentials['attributes'])

    def __init__(self, prefix, id, **attributes):  # pylint: disable=invalid-name,redefined-builtin
        self.prefix = prefix
        self.id = id  # pylint: disable=invalid-name
        self.attributes.update(**attributes)
