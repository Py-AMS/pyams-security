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

"""PyAMS_security.interfaces.names module

Package constant strings.
"""

__docformat__ = 'restructuredtext'

from pyams_security import _


SYSTEM_PREFIX = 'system'
ADMIN_USER_NAME = '__system__'
ADMIN_USER_LOGIN = 'admin'
ADMIN_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, ADMIN_USER_LOGIN)

INTERNAL_USER_NAME = '__internal__'
INTERNAL_USER_LOGIN = 'internal'
INTERNAL_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, INTERNAL_USER_LOGIN)

SYSTEM_ADMIN_ROLE = 'system.Manager'
SYSTEM_VIEWER_ROLE = 'system.Viewer'

USER_LOGIN_TITLE = _("User login")

UNKNOWN_PRINCIPAL_ID = '__UNKNOWN__'
UNCHANGED_PASSWORD = '*****'

PRINCIPAL_ID_FORMATTER = '{prefix}:{login}'
GROUP_ID_FORMATTER = '{prefix}:{group_id}'


PERMISSIONS_VOCABULARY_NAME = 'pyams_security.permissions'
ROLES_VOCABULARY_NAME = 'pyams_security.roles'
PASSWORD_MANAGERS_VOCABULARY_NAME = 'pyams_security.password.managers'


USERS_FOLDERS_VOCABULARY_NAME = 'pyams_security.plugin.users-folders'
LOCAL_GROUPS_VOCABULARY_NAME = 'pyams_security.plugin.local-groups'
