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

"""PyAMS_security.plugin.oauth module

This module is used to handle OAuth authentication.
"""

from datetime import datetime

from authomatic.providers import oauth1, oauth2
from persistent import Persistent
from pyramid.events import subscriber
from zope.container.contained import Contained
from zope.container.folder import Folder
from zope.interface import implementer
from zope.lifecycleevent import ObjectCreatedEvent
from zope.schema.fieldproperty import FieldProperty
from zope.schema.vocabulary import SimpleTerm, SimpleVocabulary
from zope.traversing.interfaces import ITraversable

from pyams_security.interfaces import IAuthenticatedPrincipalEvent, ISecurityManager, \
    IOAuthLoginConfiguration, IOAuthLoginProviderConnection, IOAuthLoginProviderInfo, \
    IOAuthUser, IOAuthUsersFolderPlugin
from pyams_security.interfaces.base import IPrincipalInfo
from pyams_security.interfaces.names import OAUTH_PROVIDERS_VOCABULARY_NAME, \
    OAUTH_USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.principal import PrincipalInfo
from pyams_utils.adapter import ContextAdapter, adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.registry import query_utility
from pyams_utils.request import check_request
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'


@implementer(IOAuthUser)
class OAuthUser(Persistent, Contained):
    # pylint: disable=too-many-instance-attributes
    """OAuth user persistent class"""

    user_id = FieldProperty(IOAuthUser['user_id'])
    provider_name = FieldProperty(IOAuthUser['provider_name'])
    username = FieldProperty(IOAuthUser['username'])
    name = FieldProperty(IOAuthUser['name'])
    first_name = FieldProperty(IOAuthUser['first_name'])
    last_name = FieldProperty(IOAuthUser['last_name'])
    nickname = FieldProperty(IOAuthUser['nickname'])
    email = FieldProperty(IOAuthUser['email'])
    timezone = FieldProperty(IOAuthUser['timezone'])
    country = FieldProperty(IOAuthUser['country'])
    city = FieldProperty(IOAuthUser['city'])
    postal_code = FieldProperty(IOAuthUser['postal_code'])
    locale = FieldProperty(IOAuthUser['locale'])
    picture = FieldProperty(IOAuthUser['picture'])
    birth_date = FieldProperty(IOAuthUser['birth_date'])
    registration_date = FieldProperty(IOAuthUser['registration_date'])

    @property
    def title(self):
        """Get user label"""
        if self.name:
            result = self.name
        elif self.first_name:
            result = '{} {}'.format(self.first_name, self.last_name or '')
        elif self.username:
            result = self.username
        else:
            result = self.nickname or self.user_id
        return result

    @property
    def title_with_source(self):
        """Get user label, including provider name"""
        return '{title} ({provider})'.format(title=self.title,
                                             provider=self.provider_name.capitalize())


@adapter_config(context=IOAuthUser, provides=IPrincipalInfo)
def oauth_user_principal_adapter(user):
    """OAuth user principal info adapter"""
    return PrincipalInfo(id="{}:{}".format(user.__parent__.prefix, user.user_id),
                         title=user.name)


@implementer(IOAuthUsersFolderPlugin)
class OAuthUsersFolder(Folder):
    """OAuth users folder"""

    prefix = FieldProperty(IOAuthUsersFolderPlugin['prefix'])
    title = FieldProperty(IOAuthUsersFolderPlugin['title'])
    enabled = FieldProperty(IOAuthUsersFolderPlugin['enabled'])

    def get_principal(self, principal_id, info=True):
        """Get principal with given ID"""
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, login = principal_id.split(':', 1)  # pylint: disable=unused-variable
        user = self.get(login)
        if user is not None:
            if info:
                return PrincipalInfo(id='{prefix}:{user_id}'.format(prefix=self.prefix,
                                                                    user_id=user.user_id),
                                     title=user.title)
            return user
        return None

    def get_all_principals(self, principal_id):
        """Get all principals for given principal ID"""
        if not self.enabled:
            return set()
        if self.get_principal(principal_id) is not None:
            return {principal_id}
        return set()

    def find_principals(self, query):
        """Find principals matching given query"""
        if not self.enabled:
            return
        if not query:
            return
        query = query.lower()
        for user in self.values():
            if (query == user.user_id or
                    query in (user.name or '').lower() or
                    query in (user.email or '').lower()):
                yield PrincipalInfo(id='{0}:{1}'.format(self.prefix, user.user_id),
                                    title=user.title_with_source)

    def get_search_results(self, data):
        """Find principals matching given search query"""
        query = data.get('query')
        if not query:
            return
        query = query.lower()
        for user in self.values():
            if (query == user.user_id or
                    query in (user.name or '').lower() or
                    query in (user.email or '').lower()):
                yield user


@vocabulary_config(name=OAUTH_USERS_FOLDERS_VOCABULARY_NAME)
class OAuthUsersFolderVocabulary(SimpleVocabulary):
    """'PyAMS OAuth users folders' vocabulary"""

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        terms = []
        manager = query_utility(ISecurityManager)
        if manager is not None:
            for name, plugin in manager.items():
                if IOAuthUsersFolderPlugin.providedBy(plugin):
                    terms.append(SimpleTerm(name, title=plugin.title))
        super(OAuthUsersFolderVocabulary, self).__init__(terms)


@subscriber(IAuthenticatedPrincipalEvent, plugin_selector=IOAuthUsersFolderPlugin)
def handle_authenticated_oauth_principal(event):  # pylint: disable=invalid-name
    """Handle authenticated OAuth principal"""
    manager = query_utility(ISecurityManager)
    oauth_folder = manager.get(manager.oauth_users_folder)
    if oauth_folder is not None:
        infos = event.infos
        if not (infos and
                'provider_name' in infos and
                'user' in infos):
            return
        user = infos['user']
        principal_id = event.principal_id
        if principal_id not in oauth_folder:
            oauth_user = OAuthUser()
            check_request().registry.notify(ObjectCreatedEvent(oauth_user))
            oauth_user.user_id = principal_id
            oauth_user.provider_name = infos['provider_name']
            oauth_user.username = user.username
            oauth_user.name = user.name
            oauth_user.first_name = user.first_name
            oauth_user.last_name = user.last_name
            oauth_user.nickname = user.nickname
            oauth_user.email = user.email
            oauth_user.timezone = str(user.timezone)
            oauth_user.country = user.country
            oauth_user.city = user.city
            oauth_user.postal_code = user.postal_code
            oauth_user.locale = user.locale
            oauth_user.picture = user.picture
            if isinstance(user.birth_date, datetime):
                oauth_user.birth_date = user.birth_date
            oauth_user.registration_date = datetime.utcnow()
            oauth_folder[principal_id] = oauth_user


#
# OAuth providers configuration
#

@implementer(IOAuthLoginProviderInfo)
class OAuthLoginProviderInfo:
    """OAuth login provider info"""

    name = FieldProperty(IOAuthLoginProviderInfo['name'])
    provider = None
    icon_class = FieldProperty(IOAuthLoginProviderInfo['icon_class'])
    icon_filename = FieldProperty(IOAuthLoginProviderInfo['icon_filename'])
    scope = FieldProperty(IOAuthLoginProviderInfo['scope'])

    def __init__(self, name, provider, **kwargs):
        self.name = name
        self.provider = provider
        for key, value in kwargs.items():
            setattr(self, key, value)


PROVIDERS_INFO = {
    'amazon': OAuthLoginProviderInfo(name=oauth2.Amazon.__name__,
                                     provider=oauth2.Amazon,
                                     icon_class='fa fa-fw fa-amazon',
                                     icon_filename='amazon.ico',
                                     scope=oauth2.Amazon.user_info_scope),
    'behance': OAuthLoginProviderInfo(name=oauth2.Behance.__name__,
                                      provider=oauth2.Behance,
                                      icon_class='fa fa-fw fa-behance-square',
                                      icon_filename='behance.ico',
                                      scope=oauth2.Behance.user_info_scope),
    'bitbucket': OAuthLoginProviderInfo(name=oauth1.Bitbucket.__name__,
                                        provider=oauth1.Bitbucket,
                                        icon_class='fa fa-fw fa-bitbucket',
                                        icon_filename='bitbucket.ico'),
    'bitly': OAuthLoginProviderInfo(name=oauth2.Bitly.__name__,
                                    provider=oauth2.Bitly,
                                    icon_class='fa fa-fw fa-share-alt',
                                    icon_filename='bitly.ico',
                                    scope=oauth2.Bitly.user_info_scope),
    'cosm': OAuthLoginProviderInfo(name=oauth2.Cosm.__name__,
                                   provider=oauth2.Cosm,
                                   icon_class='fa fa-fw fa-share-alt',
                                   icon_filename='cosm.ico',
                                   scope=oauth2.Cosm.user_info_scope),
    'devianart': OAuthLoginProviderInfo(name=oauth2.DeviantART.__name__,
                                        provider=oauth2.DeviantART,
                                        icon_class='fa fa-fw fa-deviantart',
                                        icon_filename='deviantart.ico',
                                        scope=oauth2.DeviantART.user_info_scope),
    'eventbrite': OAuthLoginProviderInfo(name=oauth2.Eventbrite.__name__,
                                         provider=oauth2.Eventbrite,
                                         icon_class='fa fa-fw fa-eventbrite',
                                         icon_filename='eventbrite.ico',
                                         scope=oauth2.Eventbrite.user_info_scope),
    'facebook': OAuthLoginProviderInfo(name=oauth2.Facebook.__name__,
                                       provider=oauth2.Facebook,
                                       icon_class='fa fa-fw fa-facebook-square',
                                       icon_filename='facebook.ico',
                                       scope=oauth2.Facebook.user_info_scope),
    'foursquare': OAuthLoginProviderInfo(name=oauth2.Foursquare.__name__,
                                         provider=oauth2.Foursquare,
                                         icon_class='fa fa-fw fa-foursquare',
                                         icon_filename='foursquare.ico',
                                         scope=oauth2.Foursquare.user_info_scope),
    'flickr': OAuthLoginProviderInfo(name=oauth1.Flickr.__name__,
                                     provider=oauth1.Flickr,
                                     icon_class='fa fa-fw fa-flickr',
                                     icon_filename='flickr.ico'),
    'github': OAuthLoginProviderInfo(name=oauth2.GitHub.__name__,
                                     provider=oauth2.GitHub,
                                     icon_class='fa fa-fw fa-github',
                                     icon_filename='github.ico',
                                     scope=oauth2.GitHub.user_info_scope),
    'google': OAuthLoginProviderInfo(name=oauth2.Google.__name__,
                                     provider=oauth2.Google,
                                     icon_class='fa fa-fw fa-google-plus',
                                     icon_filename='google.ico',
                                     scope=oauth2.Google.user_info_scope),
    'linkedin': OAuthLoginProviderInfo(name=oauth2.LinkedIn.__name__,
                                       provider=oauth2.LinkedIn,
                                       icon_class='fa fa-fw fa-linkedin-square',
                                       icon_filename='linkedin.ico',
                                       scope=oauth2.LinkedIn.user_info_scope),
    'meetup': OAuthLoginProviderInfo(name=oauth1.Meetup.__name__,
                                     provider=oauth1.Meetup,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='meetup.ico'),
    'paypal': OAuthLoginProviderInfo(name=oauth2.PayPal.__name__,
                                     provider=oauth2.PayPal,
                                     icon_class='fa fa-fw fa-paypal',
                                     icon_filename='paypal.ico',
                                     scope=oauth2.PayPal.user_info_scope),
    'plurk': OAuthLoginProviderInfo(name=oauth1.Plurk.__name__,
                                    provider=oauth1.Plurk,
                                    icon_class='fa fa-fw fa-share-alt',
                                    icon_filename='plurk.ico'),
    'reddit': OAuthLoginProviderInfo(name=oauth2.Reddit.__name__,
                                     provider=oauth2.Reddit,
                                     icon_class='fa fa-fw fa-reddit',
                                     icon_filename='reddit.ico',
                                     scope=oauth2.Reddit.user_info_scope),
    'tumblr': OAuthLoginProviderInfo(name=oauth1.Tumblr.__name__,
                                     provider=oauth1.Tumblr,
                                     icon_class='fa fa-fw fa-tumblr-square',
                                     icon_filename='tumblr.ico'),
    'twitter': OAuthLoginProviderInfo(name=oauth1.Twitter.__name__,
                                      provider=oauth1.Twitter,
                                      icon_class='fa fa-fw fa-twitter',
                                      icon_filename='twitter.ico'),
    'ubuntuone': OAuthLoginProviderInfo(name=oauth1.UbuntuOne.__name__,
                                        provider=oauth1.UbuntuOne,
                                        icon_class='fa fa-fw fa-share-alt',
                                        icon_filename='ubuntuone.ico'),
    'viadeo': OAuthLoginProviderInfo(name=oauth2.Viadeo.__name__,
                                     provider=oauth2.Viadeo,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='viadeo.ico',
                                     scope=oauth2.Viadeo.user_info_scope),
    'vimeo': OAuthLoginProviderInfo(name=oauth1.Vimeo.__name__,
                                    provider=oauth1.Vimeo,
                                    icon_class='fa fa-fw fa-vimeo-square',
                                    icon_filename='vimeo.ico'),
    'vk': OAuthLoginProviderInfo(name=oauth2.VK.__name__,
                                 provider=oauth2.VK,
                                 icon_class='fa fa-fw fa-vk',
                                 icon_filename='vk.ico',
                                 scope=oauth2.VK.user_info_scope),
    'windowslive': OAuthLoginProviderInfo(name=oauth2.WindowsLive.__name__,
                                          provider=oauth2.WindowsLive,
                                          icon_class='fa fa-fw fa-windows',
                                          icon_filename='windows_live.ico',
                                          scope=oauth2.WindowsLive.user_info_scope),
    'xero': OAuthLoginProviderInfo(name=oauth1.Xero.__name__,
                                   provider=oauth1.Xero,
                                   icon_class='fa fa-fw fa-share-alt',
                                   icon_filename='xero.ico'),
    'xing': OAuthLoginProviderInfo(name=oauth1.Xing.__name__,
                                   provider=oauth1.Xing,
                                   icon_class='fa fa-fw fa-xing',
                                   icon_filename='xing.ico'),
    'yahoo': OAuthLoginProviderInfo(name=oauth1.Yahoo.__name__,
                                    provider=oauth1.Yahoo,
                                    icon_class='fa fa-fw fa-yahoo',
                                    icon_filename='yahoo.ico'),
    'yammer': OAuthLoginProviderInfo(name=oauth2.Yammer.__name__,
                                     provider=oauth2.Yammer,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='yammer.ico',
                                     scope=oauth2.Yammer.user_info_scope),
    'yandex': OAuthLoginProviderInfo(name=oauth2.Yandex.__name__,
                                     provider=oauth2.Yandex,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='yandex.ico',
                                     scope=oauth2.Yandex.user_info_scope)
}


def get_provider_info(provider_name):
    """Get provider info matching given provider name"""
    return PROVIDERS_INFO.get(provider_name)


@vocabulary_config(name=OAUTH_PROVIDERS_VOCABULARY_NAME)
class OAuthProvidersVocabulary(SimpleVocabulary):
    """OAuth providers vocabulary"""

    def __init__(self, *args, **kwargs):  # pylint: disable=unused-argument
        terms = []
        for key, provider in PROVIDERS_INFO.items():
            terms.append(SimpleTerm(key, title=provider.name))
        terms.sort(key=lambda x: x.title)
        super(OAuthProvidersVocabulary, self).__init__(terms)


@factory_config(IOAuthLoginConfiguration)
class OAuthLoginConfiguration(Folder):
    """OAuth login configuration"""

    def get_oauth_configuration(self):
        """Get OAuth configuration of registered providers"""
        result = {}
        for provider in self.values():
            provider_info = get_provider_info(provider.provider_name)
            result[provider.provider_name] = {
                'id': provider.provider_id,
                'class_': provider_info.provider,
                'consumer_key': provider.consumer_key,
                'consumer_secret': provider.consumer_secret,
                'scope': provider_info.scope
            }
        return result


OAUTH_LOGIN_CONFIGURATION_KEY = 'pyams_security.plugin.oauth'


@adapter_config(context=ISecurityManager, provides=IOAuthLoginConfiguration)
def oauth_login_configuration_adapter(context):  # pylint: disable=invalid-name
    """OAuth login configuration adapter"""
    return get_annotation_adapter(context, OAUTH_LOGIN_CONFIGURATION_KEY,
                                  IOAuthLoginConfiguration,
                                  name='++oauth-config++')


@adapter_config(name='oauth-config', context=ISecurityManager, provides=ITraversable)
class SecurityManagerOAuthTraverser(ContextAdapter):
    """++oauth-config++ namespace traverser"""

    def traverse(self, name, furtherpath=None):  # pylint: disable=unused-argument
        """Traverse to OAuth configuration"""
        return IOAuthLoginConfiguration(self.context)


@implementer(IOAuthLoginProviderConnection)
class OAuthLoginProviderConnection(Persistent):
    """OAuth login provider connection"""

    provider_name = FieldProperty(IOAuthLoginProviderConnection['provider_name'])
    provider_id = FieldProperty(IOAuthLoginProviderConnection['provider_id'])
    consumer_key = FieldProperty(IOAuthLoginProviderConnection['consumer_key'])
    consumer_secret = FieldProperty(IOAuthLoginProviderConnection['consumer_secret'])

    def get_configuration(self):
        """Get OAuth configuration of given provider"""
        return get_provider_info(self.provider_name)
