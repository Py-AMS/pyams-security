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

"""PyAMS_security.plugin.userfolder module

This module is used to define local users.
"""

import base64
import hashlib
import hmac
import logging
import random
import sys
from datetime import datetime
from os import urandom

from persistent import Persistent
from pyramid.renderers import render
from pyramid_mailer.message import Attachment, Message
from zope.component.interfaces import ISite
from zope.container.contained import Contained
from zope.container.folder import Folder
from zope.interface import Invalid
from zope.password.interfaces import IPasswordManager
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_i18n.interfaces import II18n
from pyams_security.interfaces import ILocalUser, ISecurityManager, IUsersFolderPlugin
from pyams_security.interfaces.base import IPrincipalInfo
from pyams_security.interfaces.names import USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.interfaces.notification import INotificationSettings
from pyams_security.principal import PrincipalInfo
from pyams_utils.adapter import ContextAdapter, adapter_config
from pyams_utils.factory import factory_config
from pyams_utils.html import html_to_text
from pyams_utils.registry import get_utility, query_utility
from pyams_utils.request import check_request
from pyams_utils.traversing import get_parent
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


LOGGER = logging.getLogger('PyAMS (security)')


#
# Users folder
#

@factory_config(IUsersFolderPlugin)
class UsersFolder(Folder):
    """Local users folder"""

    prefix = FieldProperty(IUsersFolderPlugin['prefix'])
    title = FieldProperty(IUsersFolderPlugin['title'])
    enabled = FieldProperty(IUsersFolderPlugin['enabled'])

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Try to authenticate given credentials"""
        if not self.enabled:
            return None
        attrs = credentials.attributes
        login = attrs.get('login')
        principal = self.get(login)
        if principal is not None:
            password = attrs.get('password')
            if principal.check_password(password):
                return "{prefix}:{login}".format(prefix=self.prefix,
                                                 login=principal.login)
        return None

    def check_login(self, login):
        """Check if provided login is not already used"""
        if not login:
            return False
        return login not in self

    def get_principal(self, principal_id, info=True):
        """Get principal info matching given principal ID"""
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, login = principal_id.split(':', 1)  # pylint: disable=unused-variable
        user = self.get(login)
        if user is not None:
            if info:
                return PrincipalInfo(id='{prefix}:{login}'.format(prefix=self.prefix,
                                                                  login=user.login),
                                     title=user.title)
        return user

    def get_all_principals(self, principal_id):
        """Get all principals for given principal ID"""
        if not self.enabled:
            return set()
        if self.get_principal(principal_id) is not None:
            return {principal_id}
        return set()

    def find_principals(self, query, exact_match=False):
        """Get iterator of principals matching given query"""
        if not self.enabled:
            return
        if not query:
            return
        query = query.lower()
        for user in self.values():
            if exact_match:
                attrs = (user.login,)
            else:
                attrs = (user.login, user.firstname, user.lastname, user.email)
            for attr in attrs:
                if not attr:
                    continue
                if (exact_match and query == attr.lower()) or \
                        (not exact_match and query in attr.lower()):
                    yield PrincipalInfo(id='{prefix}:{login}'.format(prefix=self.prefix,
                                                                     login=user.login),
                                        title='{title} <{email}>'.format(title=user.title,
                                                                         email=user.email))
                    break

    def get_search_results(self, data):
        """Search iterator of principals matching given data"""
        query = data.get('query')
        if not query:
            return
        query = query.lower()
        for user in self.values():
            if (query == user.login or
                    query in user.firstname.lower() or
                    query in user.lastname.lower()):
                yield user


@vocabulary_config(name=USERS_FOLDERS_VOCABULARY_NAME)
class UsersFolderVocabulary(SimpleVocabulary):
    """'PyAMS users folders' vocabulary"""

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        terms = []
        manager = query_utility(ISecurityManager)
        if manager is not None:
            for name, plugin in manager.items():
                if IUsersFolderPlugin.providedBy(plugin):
                    terms.append(SimpleTerm(name, title=plugin.title))
        super(UsersFolderVocabulary, self).__init__(terms)


#
# Local users
#

def notify_user_activation(user, request=None):
    """Send mail for user activation"""
    security = query_utility(ISecurityManager)
    settings = INotificationSettings(security)
    if not settings.enable_notifications:  # pylint: disable=assignment-from-no-return
        LOGGER.info("Security notifications disabled, no message sent...")
        return
    mailer = settings.get_mailer()  # pylint: disable=assignment-from-no-return
    if mailer is None:
        LOGGER.warning("Can't find mailer utility, no notification message sent!")
        return
    if request is None:
        request = check_request()
    translate = request.localizer.translate
    i18n_settings = II18n(settings)
    message_text, template_name = None, None
    if user.self_registered:
        # pylint: disable=assignment-from-no-return
        message_text = i18n_settings.query_attribute('registration_template', request=request)
        if not message_text:
            template_name = 'templates/register-message.pt'
    elif user.wait_confirmation:
        # pylint: disable=assignment-from-no-return
        message_text = i18n_settings.query_attribute('confirmation_template', request=request)
        if not message_text:
            template_name = 'templates/register-info.pt'
    site = get_parent(request.context, ISite)
    if message_text is not None:
        message_text = message_text.format(**user.to_dict())
    elif template_name is not None:
        message_text = render(template_name, request=request, value={
            'user': user,
            'site': site,
            'settings': settings
        })
    html_body = render('templates/register-body.pt', request=request, value={
        'user': user,
        'site': site,
        'settings': settings,
        'message': message_text
    })
    message = Message(
        subject=translate(_("{prefix}Please confirm registration")).format(
            prefix="{prefix} ".format(prefix=settings.subject_prefix)
            if settings.subject_prefix else ''),
        sender='{name} <{email}>'.format(name=settings.sender_name,
                                         email=settings.sender_email),
        recipients=("{firstname} {lastname} <{email}>".format(firstname=user.firstname,
                                                              lastname=user.lastname,
                                                              email=user.email),),
        html=Attachment(data=html_body,
                        content_type='text/html; charset=utf-8',
                        disposition='inline',
                        transfer_encoding='quoted-printable'),
        body=Attachment(data=html_to_text(html_body),
                        content_type='text/plain; charset=utf-8',
                        disposition='inline',
                        transfer_encoding='quoted-printable'))
    mailer.send(message)


@factory_config(ILocalUser)
class LocalUser(Persistent, Contained):
    # pylint: disable=too-many-instance-attributes
    """Local user persistent class"""

    login = FieldProperty(ILocalUser['login'])
    email = FieldProperty(ILocalUser['email'])
    firstname = FieldProperty(ILocalUser['firstname'])
    lastname = FieldProperty(ILocalUser['lastname'])
    company_name = FieldProperty(ILocalUser['company_name'])
    _password = FieldProperty(ILocalUser['password'])
    _password_salt = None
    password_manager = FieldProperty(ILocalUser['password_manager'])
    wait_confirmation = FieldProperty(ILocalUser['wait_confirmation'])
    self_registered = FieldProperty(ILocalUser['self_registered'])
    activation_secret = FieldProperty(ILocalUser['activation_secret'])
    activation_hash = FieldProperty(ILocalUser['activation_hash'])
    activation_date = FieldProperty(ILocalUser['activation_date'])
    activated = FieldProperty(ILocalUser['activated'])

    @property
    def title(self):
        """Concatenate first and last names"""
        return '{firstname} {lastname}'.format(firstname=self.firstname,
                                               lastname=self.lastname)

    @property
    def password(self):
        """Get current encoded password"""
        return self._password

    @password.setter
    def password(self, value):
        """Encode and set user password"""
        if value:
            if value == '*****':
                return
            self._password_salt = urandom(4)
            manager = get_utility(IPasswordManager, name=self.password_manager)
            if self.password_manager == 'Plain Text':
                self._password = manager.encodePassword(value)
            else:
                self._password = manager.encodePassword(value, salt=self._password_salt)
        else:
            self._password = None

    def check_password(self, password):
        """Check given password with encoded one"""
        if not (self.activated and self.password):
            return False
        manager = query_utility(IPasswordManager, name=self.password_manager)
        if manager is None:
            return False
        return manager.checkPassword(self.password, password)

    def generate_secret(self, notify=True, request=None):
        """Generate activation secret and activation hash"""
        seed = self.activation_secret = '-'.join((hex(random.randint(0, sys.maxsize))[2:]
                                                  for i in range(5)))
        secret = hmac.new(self.password or b'', self.login.encode(), digestmod=hashlib.sha256)
        secret.update(seed.encode())
        self.activation_hash = base64.b32encode(secret.digest()).decode()
        if notify:
            notify_user_activation(self, request)

    def refresh_secret(self, notify=True, request=None):
        """Refresh activation secret and activation hash"""
        self.password = None
        self.generate_secret(notify, request)
        self.wait_confirmation = True
        self.activation_date = None
        self.activated = False

    def check_activation(self, hash, login, password):  # pylint: disable=redefined-builtin
        """Check is given hash is matching stored one, and activate user"""
        if self.self_registered:
            # If principal was registered by it's own, we check activation hash
            # with given login and password
            manager = get_utility(IPasswordManager, name=self.password_manager)
            password = manager.encodePassword(password, salt=self._password_salt)
            secret = hmac.new(password, login.encode(), digestmod=hashlib.sha256)
            secret.update(self.activation_secret.encode())
            activation_hash = base64.b32encode(secret.digest()).decode()
            if hash != activation_hash:
                raise Invalid(_("Can't activate profile with given params!"))
        else:
            # If principal was registered by a site manager, just check that
            # hash is matching stored one and update user password...
            if hash != self.activation_hash:
                raise Invalid(_("Can't activate profile with given params!"))
            self.password = password
        self.wait_confirmation = False
        self.activation_date = datetime.utcnow()
        self.activated = True

    def to_dict(self):
        """Get main user properties as mapping"""
        return {
            'login': self.login,
            'email': self.email,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'title': self.title,
            'company_name': self.company_name
        }


@adapter_config(required=ILocalUser, provides=IPrincipalInfo)
def user_principal_info_adapter(user):
    """User principal info adapter"""
    return PrincipalInfo(id="{prefix}:{login}".format(prefix=user.__parent__.prefix,
                                                      login=user.login),
                         title=user.title)


try:
    from pyams_mail.interfaces import IPrincipalMailInfo
except ImportError:
    pass
else:
    @adapter_config(required=ILocalUser, provides=IPrincipalMailInfo)
    class UserPrincipalMailInfoAdapter(ContextAdapter):
        """User principal mail info adapter"""

        def get_addresses(self):
            """Get user email address"""
            yield ('{0} {1}'.format(self.context.firstname,
                                    self.context.lastname),
                   self.context.email)
