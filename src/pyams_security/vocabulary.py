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

"""PyAMS_security.vocabulary module

"""

from zope.componentvocabulary.vocabulary import UtilityVocabulary
from zope.password.interfaces import IPasswordManager

from pyams_security.interfaces import PASSWORD_MANAGERS_VOCABULARY_NAME
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'


@vocabulary_config(name=PASSWORD_MANAGERS_VOCABULARY_NAME)
class PasswordManagerVocabulary(UtilityVocabulary):
    """Password managers vocabulary"""

    interface = IPasswordManager
    nameOnly = True
