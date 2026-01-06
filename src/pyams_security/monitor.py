# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

from pyams_security.interfaces import ISecurityManager
from pyams_utils.factory import create_object
from pyams_utils.interfaces.monitor import IMonitorExtension, IMonitorExtensionStatus
from pyams_utils.registry import query_utility, utility_config

__docformat__ = 'restructuredtext'


@utility_config(name='pyams_security.monitor',
                provides=IMonitorExtension)
class SecurityMonitor:
    """Security manager monitor utility"""
    
    def get_status(self, request):
        sm = query_utility(ISecurityManager)
        if sm is None:
            yield create_object(IMonitorExtensionStatus,
                                handler='pyams_security.monitor:manager',
                                status='DOWN',
                                message='Missing security manager')
        else:
            yield create_object(IMonitorExtensionStatus,
                                handler='pyams_security.monitor:manager',
                                status='UP')
