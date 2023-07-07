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
from zope.interface import Attribute, Interface

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


class IUserRegistrationViews(Interface):
    """User registration views URL interface"""

    register_view = Attribute("Register view URL")
    register_ok_view = Attribute("Register OK view URL")
    register_confirm_view = Attribute("Registration confirmation view URL")
    register_final_view = Attribute("Registration final view")
    password_reset_view = Attribute("Password reset view")
    password_reset_final_view = Attribute("Password reset final view")
    password_change_view = Attribute("Password change view")
    password_change_final_view = Attribute("Password change final view")
