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

"""PyAMS_site.interfaces.profile module

"""

from zope.annotation.interfaces import IAttributeAnnotatable

from pyams_file.schema import ThumbnailImageField


__docformat__ = 'restructuredtext'

from pyams_site import _


PUBLIC_PROFILE_KEY = 'pyams_security.public_profile'


class IPublicProfile(IAttributeAnnotatable):
    """User public profile preferences"""

    avatar = ThumbnailImageField(title=_("Profile's avatar"),
                                 description=_("This picture will be associated to your user "
                                               "profile"),
                                 required=False)
