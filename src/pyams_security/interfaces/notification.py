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

"""PyAMS_security.interfaces.notification module

This module defines notifications related interfaces.
"""

from zope.annotation.interfaces import IAttributeAnnotatable
from zope.interface import Invalid, invariant
from zope.schema import Bool, Choice, Text, TextLine

from pyams_i18n.schema import I18nHTMLField
from pyams_mail.interfaces import MAILERS_VOCABULARY_NAME


__docformat__ = 'restructuredtext'

from pyams_security import _


class INotificationSettings(IAttributeAnnotatable):
    """Mailer notification settings interface"""

    enable_notifications = Bool(title=_("Enable notifications?"),
                                description=_("If 'no', mail notifications will be disabled"),
                                required=True,
                                default=False)

    mailer = Choice(title=_("Mailer utility"),
                    description=_("Mail delivery utility used to send notifications"),
                    required=False,
                    vocabulary=MAILERS_VOCABULARY_NAME)

    @invariant
    def check_mailer(self):
        """Check mailer to enable notifications"""
        if self.enable_notifications and not self.mailer:
            raise Invalid(_("Notifications can't be enabled without mailer utility"))

    def get_mailer(self):
        """Return mailer utility"""

    service_name = TextLine(title=_("Service name"),
                            description=_("Name of service as defined in registration mail "
                                          "subject"),
                            required=True)

    service_owner = TextLine(title=_("Service owner"),
                             description=_("Name of the entity providing this service, which "
                                           "will be visible in notifications messages"),
                             required=True)

    sender_name = TextLine(title=_("Sender name"),
                           description=_("Visible name of registration mail sender"),
                           required=True)

    sender_email = TextLine(title=_("Sender email"),
                            description=_("Email address of registration mail sender"),
                            required=True)

    subject_prefix = TextLine(title=_("Subject prefix"),
                              description=_("This prefix will be inserted into subject prefix of "
                                            "each notification message"),
                              required=False)

    confirmation_template = I18nHTMLField(
        title=_("Confirmation template"),
        description=_("This template will be used instead of default template to send "
                      "notification when a user is registered by a system administrator; you can "
                      "use some user properties into the message body, like: {login}, {email}, "
                      "{firstname}, {lastname}, {title} or {company_name}; message activation "
                      "link and footer are added automatically"),
        required=False)

    registration_template = I18nHTMLField(
        title=_("Registration template"),
        description=_("This template will be used instead of default template to send "
                      "notificaiton when a user is auto-registered; you can use some user "
                      "properties into the message body, like: {login}, {email}, {firstname}, "
                      "{lastname}, {title} or {company_name}; message activation link and footer "
                      "are added automatically"),
        required=False)

    signature = Text(title=_("Email signature"),
                     description=_("Text displayed in email footer"),
                     required=False)
