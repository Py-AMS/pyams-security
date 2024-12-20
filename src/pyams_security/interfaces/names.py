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
'''System principals prefix'''

ADMIN_USER_NAME = '__system__'
'''System manager principal name'''

ADMIN_USER_LOGIN = 'admin'
'''System manager principal login'''

ADMIN_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, ADMIN_USER_LOGIN)
'''System manager principal ID'''


INTERNAL_USER_NAME = '__internal__'
'''Internal principal name'''

INTERNAL_USER_LOGIN = 'internal'
'''Internal principal login'''

INTERNAL_USER_ID = '{0}:{1}'.format(SYSTEM_PREFIX, INTERNAL_USER_LOGIN)
'''Internal principal ID'''


SYSTEM_ADMIN_ROLE = 'system.Manager'
'''System manager role ID'''

SYSTEM_VIEWER_ROLE = 'system.Viewer'
'''System viewer role ID'''


INTERNAL_API_ROLE = 'system.InternalAPI'
'''Internal API user role ID'''

PUBLIC_API_ROLE = 'system.PublicAPI'
'''Public API user role ID'''


USER_LOGIN_TITLE = _("User login")
'''User login form title'''


UNKNOWN_PRINCIPAL_ID = '__UNKNOWN__'
'''Unknown principal ID'''

UNCHANGED_PASSWORD = '*****'
'''Unchanged password static value'''


PRINCIPAL_ID_FORMATTER = '{prefix}:{login}'
'''Principal ID formatter string'''

GROUP_ID_FORMATTER = '{prefix}:{group_id}'
'''Group ID formatter string'''


PERMISSIONS_VOCABULARY_NAME = 'pyams_security.permissions'
'''Permissions vocabulary name'''

ROLES_VOCABULARY_NAME = 'pyams_security.roles'
'''Roles vocabulary name'''

PASSWORD_MANAGERS_VOCABULARY_NAME = 'pyams_security.password.managers'
'''Password managers vocabulary name'''


USERS_FOLDERS_VOCABULARY_NAME = 'pyams_security.plugin.users-folders'
'''Users folders vocabulary name'''

LOCAL_GROUPS_VOCABULARY_NAME = 'pyams_security.plugin.local-groups'
'''Local groups vocabulary name'''
