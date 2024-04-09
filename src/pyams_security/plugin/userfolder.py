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
from datetime import datetime, timedelta
from os import urandom

from persistent import Persistent
from pyramid.events import subscriber
from pyramid.renderers import render
from pyramid_mailer.message import Attachment, Message
from zope.component.interfaces import ISite
from zope.container.contained import Contained
from zope.container.folder import Folder
from zope.interface import Invalid
from zope.lifecycleevent.interfaces import IObjectRemovedEvent
from zope.password.interfaces import IPasswordManager
from zope.principalannotation.interfaces import IPrincipalAnnotationUtility
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary

from pyams_i18n.interfaces import II18n
from pyams_security.interfaces import ISecurityManager
from pyams_security.interfaces.base import IPrincipalInfo
from pyams_security.interfaces.names import PRINCIPAL_ID_FORMATTER, UNCHANGED_PASSWORD, \
    USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.interfaces.notification import INotificationSettings
from pyams_security.interfaces.plugin import ILocalUser, IUsersFolderPlugin, LOCKED_ACCOUNT_PASSWORD, SALT_SIZE
from pyams_security.principal import PrincipalInfo
from pyams_security.interfaces.profile import IUserRegistrationViews
from pyams_utils.adapter import ContextAdapter, adapter_config
from pyams_utils.factory import factory_config
from pyams_utils.html import html_to_text
from pyams_utils.registry import get_pyramid_registry, get_utility, query_utility
from pyams_utils.request import check_request
from pyams_utils.timezone import tztime
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

    case_insensitive_login = FieldProperty(IUsersFolderPlugin['case_insensitive_login'])

    def get(self, key, default=None):
        if self.case_insensitive_login:
            key = key.lower()
        return super().get(key, default)

    def __contains__(self, item):
        if self.case_insensitive_login:
            item = item.lower()
        return super().__contains__(item)

    def __setitem__(self, key, value):
        if self.case_insensitive_login:
            key = key.lower()
        super().__setitem__(key, value)

    def authenticate(self, credentials, request):  # pylint: disable=unused-argument
        """Try to authenticate given credentials"""
        if not self.enabled:
            return None
        attrs = credentials.attributes
        login = attrs.get('login')
        if not login:
            return None
        principal = self.get(login)
        if principal is not None:
            password = attrs.get('password')
            if principal.check_password(password):
                return PRINCIPAL_ID_FORMATTER.format(prefix=self.prefix,
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
                return PrincipalInfo(id=PRINCIPAL_ID_FORMATTER.format(prefix=self.prefix,
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
                    yield PrincipalInfo(id=PRINCIPAL_ID_FORMATTER.format(prefix=self.prefix,
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
        super().__init__(terms)


#
# Local users
#

def send_message(subject, template, user, request, **params):
    """Send HTML message to user"""
    security = get_utility(ISecurityManager)
    settings = INotificationSettings(security)
    if not settings.enable_notifications:  # pylint: disable=assignment-from-no-return
        LOGGER.info("Security notifications disabled, no message sent...")
        return
    mailer = settings.get_mailer()  # pylint: disable=assignment-from-no-return
    if mailer is None:
        LOGGER.warning("Can't find mailer utility, no notification message sent!")
        return
    site = get_parent(request.context, ISite)
    value = {
        'site': site,
        'settings': settings,
        'user': user
    }
    value.update(params)
    html_body = render(template, request=request, value=value)
    translate = request.localizer.translate
    message = Message(
        subject=translate(_("{prefix}{subject}")).format(
            prefix="{prefix} ".format(prefix=settings.subject_prefix)
                if settings.subject_prefix else '',
            subject=translate(subject)),
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


def notify_user_activation(user, request=None):
    """Send mail for user activation"""
    security = get_utility(ISecurityManager)
    settings = INotificationSettings(security)
    if request is None:
        request = check_request()
    # translate = request.localizer.translate
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
    if message_text is not None:
        message_text = message_text.format(**user.to_dict())
    elif template_name is not None:
        message_text = render(template_name, request=request, value={
            'user': user,
            'settings': settings
        })
    registry = get_pyramid_registry()
    if hasattr(request, 'root'):
        views = registry.getMultiAdapter((request.root, request), IUserRegistrationViews)
        send_message(_("Please confirm registration"), 'templates/register-body.pt', user, request,
                     message=message_text,
                     confirm_url=views.register_confirm_view)
    else:
        send_message(_("Please confirm registration"), 'templates/register-body.pt', user, request,
                     message=message_text,
                     confirm_url=None)


def notify_password_reset(user, request=None):
    """Send mail for user password reset"""
    if request is None:
        request = check_request()
    registry = get_pyramid_registry()
    views = registry.getMultiAdapter((request.root, request), IUserRegistrationViews)
    send_message(_("Password reset"), 'templates/password-reset.pt', user, request,
                 change_url=views.password_change_view)


@factory_config(ILocalUser)
class LocalUser(Persistent, Contained):
    # pylint: disable=too-many-instance-attributes
    """Local user persistent class"""

    login = FieldProperty(ILocalUser['login'])
    email = FieldProperty(ILocalUser['email'])
    firstname = FieldProperty(ILocalUser['firstname'])
    lastname = FieldProperty(ILocalUser['lastname'])
    company_name = FieldProperty(ILocalUser['company_name'])
    password_manager = FieldProperty(ILocalUser['password_manager'])
    _password = FieldProperty(ILocalUser['password'])
    _password_salt = None
    wait_confirmation = FieldProperty(ILocalUser['wait_confirmation'])
    self_registered = FieldProperty(ILocalUser['self_registered'])
    activation_secret = FieldProperty(ILocalUser['activation_secret'])
    activation_hash = FieldProperty(ILocalUser['activation_hash'])
    activated = FieldProperty(ILocalUser['activated'])
    activation_date = FieldProperty(ILocalUser['activation_date'])
    password_hash = FieldProperty(ILocalUser['password_hash'])
    password_hash_validity = FieldProperty(ILocalUser['password_hash_validity'])

    @property
    def title(self):
        """Concatenate first and last names"""
        return f'{self.firstname} {self.lastname}'

    @property
    def password(self):
        """Get current encoded password"""
        return self._password

    @password.setter
    def password(self, value):
        """Encode and set user password"""
        if value:
            if value == UNCHANGED_PASSWORD:
                return
            self._password_salt = urandom(SALT_SIZE.get(self.password_manager, 4))
            manager = get_utility(IPasswordManager, name=self.password_manager)
            if self.password_manager == 'Plain Text':
                self._password = manager.encodePassword(value)
            else:
                self._password = manager.encodePassword(value, salt=self._password_salt)
        else:
            self._password = None

    def check_password(self, password):
        """Check given password with encoded one"""
        if password == LOCKED_ACCOUNT_PASSWORD:
            return False
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

    def generate_reset_hash(self, notify=True, request=None):
        """Password reset request"""
        secret = hmac.new(self.login.encode(), (self.activation_secret or '').encode(),
                          digestmod=hashlib.sha512)
        self.password_hash = base64.b32encode(secret.digest()).decode()
        self.password_hash_validity = tztime(datetime.utcnow())
        if notify:
            notify_password_reset(self, request)

    def reset_password(self, hash, password):  # pylint: disable=redefined-builtin
        """Check password reset for given settings"""
        if not self.password_hash:
            raise Invalid(_("Invalid reset request!"))
        if hash != self.password_hash:
            raise Invalid(_("Can't reset password with given params!"))
        validity_expiration = self.password_hash_validity + timedelta(days=7)
        if tztime(datetime.utcnow()) > validity_expiration:
            raise Invalid(_("Your password reset hash is no longer valid!"))
        self.password = password
        self.password_hash = None
        self.password_hash_validity = None

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


@adapter_config(required=ILocalUser,
                provides=IPrincipalInfo)
def user_principal_info_adapter(user):
    """User principal info adapter"""
    return PrincipalInfo(id=PRINCIPAL_ID_FORMATTER.format(prefix=user.__parent__.prefix,
                                                          login=user.login),
                         title=user.title)


try:
    from pyams_mail.interfaces import IPrincipalMailInfo
except ImportError:
    pass
else:
    @adapter_config(required=ILocalUser,
                    provides=IPrincipalMailInfo)
    class UserPrincipalMailInfoAdapter(ContextAdapter):
        """User principal mail info adapter"""

        def get_addresses(self):
            """Get user email address"""
            yield self.context.title, self.context.email


@subscriber(IObjectRemovedEvent, context_selector=ILocalUser)
def handle_removed_local_user(event: IObjectRemovedEvent):
    """Handle local user delete"""
    user = event.object
    principal = IPrincipalInfo(user)
    utility = get_utility(IPrincipalAnnotationUtility)
    if utility.hasAnnotations(principal):
        del utility.annotations[principal.id]
