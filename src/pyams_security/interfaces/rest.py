#
# Copyright (c) 2015-2022 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.interfaces.rest module

This module defines interfaces of components which are used to improve security of
REST services using CORS requests.
"""

from zope.interface import Interface
from zope.schema import Bool

from pyams_utils.schema import TextLineListField


__docformat__ = 'restructuredtext'

from pyams_security import _


CORS_CONFIGURATION_KEY = 'pyams_security.cors'
"""CORS configuration annotation key"""


class ICORSSecurityInfo(Interface):
    """Base CORS security interface"""

    restrict_origins = Bool(title=_("Check request origin"),
                            description=_("If enabled, REST API will check requests against "
                                          "currently allowed origins, and raise an HTTP "
                                          "forbidden exception if not allowed"),
                            required=True,
                            default=True)

    allowed_origins = TextLineListField(title=_("Allowed origins"),
                                        description=_("List of allowed origins URLs using CORS "
                                                      "requests"),
                                        required=False)

    def check_origin(self, request):
        """Check origin of given request

        Raise an HTTP exception if request origin is not allowed.
        """

    def set_headers(self, request):
        """Set CORS headers of given request"""
