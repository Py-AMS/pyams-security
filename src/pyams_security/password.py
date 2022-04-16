#
# Copyright (c) 2015-2021 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.password module

This module defines custom passwords managers.
"""

from base64 import standard_b64decode, standard_b64encode
from hashlib import pbkdf2_hmac, sha512
from hmac import compare_digest
from os import urandom

from zope.password.interfaces import IPasswordManager
from zope.password.password import _PrefixedPasswordManager, _encoder

from pyams_security.interfaces.plugin import SALT_SIZE
from pyams_utils.registry import utility_config


__docformat__ = 'restructuredtext'


@utility_config(name='SSHA512',
                provides=IPasswordManager)
class SSHA512PasswordManager(_PrefixedPasswordManager):
    """SSHA512 password manager"""

    _prefix = b'{SSHA512}'

    def encodePassword(self, password, salt=None):  # pylint: disable=arguments-differ
        if salt is None:
            salt = urandom(SALT_SIZE.get('SSHA512', 32))
        elif not isinstance(salt, bytes):
            salt = _encoder(salt)
        hashcode = sha512(_encoder(password))
        hashcode.update(salt)
        return self._prefix + standard_b64encode(hashcode.digest() + salt)

    def checkPassword(self, encoded_password, password):
        # standard_b64decode() cannot handle unicode input string.
        encoded_password = _encoder(encoded_password)[9:]
        byte_string = standard_b64decode(encoded_password)
        salt = byte_string[64:]
        return compare_digest(encoded_password,
                              self.encodePassword(password, salt)[9:])


@utility_config(name='PBKDF2',
                provides=IPasswordManager)
class PBKDF2PasswordManager(_PrefixedPasswordManager):
    """PBKDF2-HMAC password manager"""

    _prefix = b'{PBKDF2}'

    def encodePassword(self, password, salt=None):  # pylint: disable=arguments-differ
        if salt is None:
            salt = urandom(SALT_SIZE.get('PBKDF2', 32))
        elif not isinstance(salt, bytes):
            salt = _encoder(salt)
        hashcode = pbkdf2_hmac('sha512', _encoder(password), salt, 100000)
        return self._prefix + standard_b64encode(hashcode + salt)

    def checkPassword(self, encoded_password, password):
        # standard_b64decode() cannot handle unicode input string.
        encoded_password = _encoder(encoded_password)[8:]
        byte_string = standard_b64decode(encoded_password)
        salt = byte_string[64:]
        return compare_digest(encoded_password,
                              self.encodePassword(password, salt)[8:])
