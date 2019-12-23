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

"""PyAMS_security.plugin.http module

This module defines an HTTP authentication module.
"""

import base64
import re

from pyams_security.credential import Credentials
from pyams_security.interfaces import ICredentialsPlugin
from pyams_utils.registry import utility_config
from pyams_utils.wsgi import wsgi_environ_cache


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


ENVKEY_PARSED_CREDENTIALS = "pyams_security.http.basic.credentials"

CUSTOM_LOGIN = re.compile(r'^{(.*)}\.?(.*)')


@utility_config(name='http', provides=ICredentialsPlugin)
class HttpBasicCredentialsPlugin:
    """HTTP basic credentials plug-in

    This credential plug-in is mainly used by automation processes using
    XML-RPC or JSON-RPC requests launched from batch scripts.

    Copied from pyramid_httpauth package.
    """

    prefix = 'http'
    title = _("HTTP Basic credentials")
    enabled = True

    @wsgi_environ_cache(ENVKEY_PARSED_CREDENTIALS)
    def extract_credentials(self, request, **kwargs):  # pylint: disable=unused-argument
        """Extract login/password credentials from given request"""
        auth = request.headers.get('Authorization')
        if not auth:
            return None
        try:
            scheme, params = auth.split(' ', 1)
            if scheme.lower() != 'basic':
                return None
            token_bytes = base64.b64decode(params.strip())
            try:
                token = token_bytes.decode('utf-8')
            except UnicodeDecodeError:
                token = token_bytes.decode('latin-1')
            login, password = token.split(':', 1)
            if login.startswith('{'):
                principal_id = CUSTOM_LOGIN.sub(r'\1:\2', login)
                prefix, login = principal_id.split(':')  # pylint: disable=unused-variable
            else:
                principal_id = login
            return Credentials(self.prefix, principal_id, login=login, password=password)
        except (ValueError, TypeError):
            return None
