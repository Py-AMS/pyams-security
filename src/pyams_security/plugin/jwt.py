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

"""PyAMS_security.plugin.jwt module

This module provides a JWT authentication plug-in.
"""

import logging
from datetime import datetime, timedelta

import jwt
from ZODB.POSException import ConnectionStateError
from jwt import InvalidTokenError

from pyams_security.credential import Credentials
from pyams_security.interfaces import ICredentialsPlugin, IJWTAuthenticationPlugin, ISecurityManager
from pyams_utils.registry import query_utility, utility_config
from pyams_utils.wsgi import wsgi_environ_cache


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


LOGGER = logging.getLogger('PyAMS (security)')

ENVKEY_PARSED_CREDENTIALS = "pyams_security.jwt.token"


@utility_config(provides=IJWTAuthenticationPlugin)
@utility_config(name='jwt', provides=ICredentialsPlugin)
class JWTAuthenticationPlugin:
    """JWT authentication policy"""

    prefix = 'jwt'
    title = _("JWT authentication credentials")
    enabled = True

    audience = None
    leeway = 0
    http_header = 'Authorization'
    auth_type = 'JWT'
    callback = None
    json_encoder = None

    @property
    def security_manager(self):
        """Security manager getter"""
        try:
            return query_utility(ISecurityManager)
        except ConnectionStateError:
            return None

    def is_enabled(self):
        """Check if JWT authentication is enabled in security manager"""
        manager = self.security_manager
        return manager.enable_jwt_login if (manager is not None) else False

    @property
    def expiration(self):
        """Get default security manager expiration"""
        return self.security_manager.jwt_expiration

    def create_token(self, principal, expiration=None, audience=None, **claims):
        """Create JWT token"""
        if not self.is_enabled():
            return None
        security_manager = self.security_manager
        payload = {}
        payload.update(claims)
        payload['sub'] = principal
        payload['iat'] = iat = datetime.utcnow()
        expiration = expiration or self.expiration
        if expiration:
            if not isinstance(expiration, timedelta):
                expiration = timedelta(seconds=expiration)
            payload['exp'] = iat + expiration
        audience = audience or self.audience
        if audience:
            payload['aud'] = audience
        algorithm = security_manager.jwt_algorithm
        if algorithm.startswith('HS'):
            key = security_manager.jwt_secret
        else:  # RS256
            key = security_manager.jwt_private_key
        token = jwt.encode(payload, key, algorithm=algorithm, json_encoder=self.json_encoder)
        if not isinstance(token, str):
            token = token.decode('ascii')
        return token

    def get_claims(self, request):  # pylint: disable=too-many-return-statements
        """Get JWT claims"""
        if not self.is_enabled():
            return {}
        if self.http_header == 'Authorization':
            try:
                if request.authorization is None:
                    return {}
            except (ValueError, AttributeError):  # invalid authorization header
                return {}
            (auth_type, token) = request.authorization
            if auth_type != self.auth_type:
                return {}
        else:
            token = request.headers.get(self.http_header)
        if not token:
            return {}
        try:
            security_manager = self.security_manager
            algorithm = security_manager.jwt_algorithm
            if algorithm.startswith('HS'):
                key = security_manager.jwt_secret
            else:  # RS256/RS512
                key = security_manager.jwt_public_key
            claims = jwt.decode(token, key, algorithms=[algorithm],
                                leeway=self.leeway, audience=self.audience)
            return claims
        except InvalidTokenError as exc:
            LOGGER.warning('Invalid JWT token from %s: %s', request.remote_addr, exc)
            return {}

    @wsgi_environ_cache(ENVKEY_PARSED_CREDENTIALS)
    def extract_credentials(self, request, **kwargs):  # pylint: disable=unused-argument
        """Extract principal ID from given request"""
        claims = self.get_claims(request)
        return Credentials(self.prefix,
                           claims.get('sub'),
                           login=claims.get('login')) if claims else None

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Authenticate JWT token"""
        claims = self.get_claims(request)
        return claims.get('sub') if claims else None

    def unauthenticated_userid(self, request):
        """Get unauthenticated user ID"""
        claims = self.get_claims(request)
        return claims.get('sub') if claims else None


def create_jwt_token(request, principal, expiration=None, audience=None, **claims):
    # pylint: disable=unused-argument
    """Create JWT token"""
    policy = query_utility(IJWTAuthenticationPlugin)
    if (policy is not None) and policy.is_enabled():
        return policy.create_token(principal, expiration, audience, **claims)
    return None


def get_jwt_claims(request):
    """Get JWT claims"""
    policy = query_utility(IJWTAuthenticationPlugin)
    if (policy is not None) and policy.is_enabled():
        return policy.get_claims(request)
    return {}
