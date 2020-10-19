#
# Copyright (c) 2015-2019 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""
Generic test cases for pyams_security doctests
"""

import base64
import os
import sys

from pyramid.testing import DummyRequest, setUp
from pyramid.threadlocal import manager
from pyramid_mailer import IMailer
from pyramid_mailer.mailer import DummyMailer
from zope.interface import Interface

from pyams_i18n.attr import I18nAttributeAdapter
from pyams_i18n.interfaces import II18n
from pyams_security.interfaces import IRoleProtectedObject, \
    ISecurityManager
from pyams_security.interfaces.notification import INotificationSettings
from pyams_security.notification import NotificationSettings, security_notification_factory
from pyams_security.security import RoleProtectedObject
from pyams_utils.factory import register_factory
from pyams_utils.registry import set_local_registry


__docformat__ = 'restructuredtext'


def get_package_dir(value):
    """Get package directory"""
    package_dir = os.path.split(value)[0]
    if package_dir not in sys.path:
        sys.path.append(package_dir)
    return package_dir


def setup_tests_registry():
    """Initialize required adapters and utilities for testing"""
    config = setUp(hook_zca=True)
    registry = config.registry
    # register adapters
    registry.registerAdapter(I18nAttributeAdapter, (Interface, ), II18n)
    # register security factory
    register_factory(IRoleProtectedObject, RoleProtectedObject)
    # register notification components
    mailer = DummyMailer()
    register_factory(INotificationSettings, NotificationSettings)
    registry.registerUtility(mailer, provided=IMailer, name='mailer')
    registry.registerAdapter(security_notification_factory, (ISecurityManager, ),
                             provided=INotificationSettings)
    return config


def new_test_request(login, password, method='basic', context=None, registry=None):
    """Create test request with HTTP authorization header"""
    auth = base64.b64encode('{}:{}'.format(login, password).encode()).decode()
    request = DummyRequest(headers={'Authorization': '{} {}'.format(method, auth)},
                           context=context)
    if registry is not None:
        manager.clear()
        manager.push({
            'registry': registry,
            'request': request
        })
    return request
