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

"""PyAMS_security.plugin main module

This module enables a "plugin_selector" subscriber predicate, which can be used to
filter plugins events based on plug-in name or interface.
"""

__docformat__ = 'restructuredtext'


class PluginSelector:
    """Plug-in based event selector

    This selector can be used by subscriber to filter authentication
    events based on the name of the plug-in which fired the event.
    """

    def __init__(self, name, config):  # pylint: disable=unused-argument
        self.plugin = name

    def text(self):
        """Predicate text output"""
        return 'plugin_selector = %s' % str(self.plugin)

    phash = text

    def __call__(self, event):
        if isinstance(self.plugin, str):
            return event.plugin == self.plugin
        try:
            if self.plugin.providedBy(event.plugin):
                return True
        except (AttributeError, TypeError):
            if isinstance(event.plugin, self.plugin):
                return True
        return False
