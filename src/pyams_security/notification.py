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

"""PyAMS_security.notification module

This module handles notificaiton settings.
"""

from persistent import Persistent
from pyramid_mailer import IMailer
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.notification import INotificationSettings
from pyams_utils.adapter import adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'


@factory_config(INotificationSettings)
class NotificationSettings(Persistent):
    """Notification settings"""

    enable_notifications = FieldProperty(INotificationSettings['enable_notifications'])
    mailer = FieldProperty(INotificationSettings['mailer'])
    service_name = FieldProperty(INotificationSettings['service_name'])
    service_owner = FieldProperty(INotificationSettings['service_owner'])
    sender_name = FieldProperty(INotificationSettings['sender_name'])
    sender_email = FieldProperty(INotificationSettings['sender_email'])
    subject_prefix = FieldProperty(INotificationSettings['subject_prefix'])
    confirmation_template = FieldProperty(INotificationSettings['confirmation_template'])
    registration_template = FieldProperty(INotificationSettings['registration_template'])
    signature = FieldProperty(INotificationSettings['signature'])

    def get_mailer(self):
        """Get mailer utility matching current selection"""
        if self.mailer is not None:
            return query_utility(IMailer, name=self.mailer)
        return None


NOTIFICATIONS_KEY = 'pyams_security.notifications'


@adapter_config(required=ISecurityManager, provides=INotificationSettings)
def security_notification_factory(context):
    """Security manager notifications factory adapter"""
    return get_annotation_adapter(context, NOTIFICATIONS_KEY, INotificationSettings, locate=False)
