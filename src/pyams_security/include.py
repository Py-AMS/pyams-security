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

"""PyAMS_security.include module

This module is used for Pyramid integration.
"""

from pyramid.settings import asbool
from zope.interface import classImplements
from zope.password.interfaces import IPasswordManager
from zope.password.password import MD5PasswordManager, PlainTextPasswordManager, \
    SHA1PasswordManager, SSHAPasswordManager

from pyams_security.interfaces import ADMIN_USER_ID, IDefaultProtectionPolicy, SYSTEM_ADMIN_ROLE
from pyams_security.interfaces.base import MANAGE_PERMISSION, MANAGE_ROLES_PERMISSION, \
    MANAGE_SECURITY_PERMISSION, MANAGE_SYSTEM_PERMISSION, PUBLIC_PERMISSION, \
    VIEW_PERMISSION, VIEW_SYSTEM_PERMISSION
from pyams_security.permission import register_permission
from pyams_security.plugin import PluginSelector
from pyams_security.role import RoleSelector, register_role
from pyams_security.security import ProtectedObjectMixin
from pyams_security.utility import get_principal
from pyams_site.site import BaseSiteRoot


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


def include_package(config):
    """Pyramid package include"""

    # add translations
    config.add_translation_dirs('pyams_security:locales')

    config.registry.registerUtility(factory=PlainTextPasswordManager,
                                    provided=IPasswordManager, name='Plain Text')
    config.registry.registerUtility(factory=MD5PasswordManager,
                                    provided=IPasswordManager, name='MD5')
    config.registry.registerUtility(factory=SHA1PasswordManager,
                                    provided=IPasswordManager, name='SHA1')
    config.registry.registerUtility(factory=SSHAPasswordManager,
                                    provided=IPasswordManager, name='SSHA')

    # add configuration directives
    config.add_directive('register_permission', register_permission)
    config.add_directive('register_role', register_role)
    config.add_request_method(get_principal, 'principal', reify=True)

    # add subscribers predicate
    config.add_subscriber_predicate('role_selector', RoleSelector)
    config.add_subscriber_predicate('plugin_selector', PluginSelector)

    # register standard permissions
    config.register_permission({
        'id': PUBLIC_PERMISSION,
        'title': _("View public contents")
    })
    config.register_permission({
        'id': VIEW_PERMISSION,
        'title': _("View protected contents")
    })
    config.register_permission({
        'id': MANAGE_PERMISSION,
        'title': _("Manage contents properties")
    })
    config.register_permission({
        'id': VIEW_SYSTEM_PERMISSION,
        'title': _("View management screens")
    })
    config.register_permission({
        'id': MANAGE_SYSTEM_PERMISSION,
        'title': _("Manage system properties")
    })

    config.register_permission({
        'id': MANAGE_SECURITY_PERMISSION,
        'title': _("Manage security")
    })
    config.register_permission({
        'id': MANAGE_ROLES_PERMISSION,
        'title': _("Manage roles")
    })

    # register standard roles
    config.register_role({
        'id': SYSTEM_ADMIN_ROLE,
        'title': _("System manager (role)"),
        'permissions': {
            PUBLIC_PERMISSION, VIEW_PERMISSION, MANAGE_PERMISSION,
            MANAGE_SYSTEM_PERMISSION, VIEW_SYSTEM_PERMISSION, MANAGE_SECURITY_PERMISSION,
            MANAGE_ROLES_PERMISSION
        },
        'managers': {
            ADMIN_USER_ID,
            'role:{0}'.format(SYSTEM_ADMIN_ROLE)
        }
    })

    # custom classes implementations
    if not asbool(config.registry.settings.get('pyams.security.disable-default-policy', False)):
        classImplements(BaseSiteRoot, IDefaultProtectionPolicy)
        BaseSiteRoot.__acl__ = ProtectedObjectMixin.__acl__

    config.scan()
