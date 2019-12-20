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

"""PyAMS_security.plugin.social module

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

from pyams_security.interfaces import IAuthenticatedPrincipalEvent, ISecurityManager, ISocialLoginConfiguration, ISocialLoginProviderConnection, \
    ISocialLoginProviderInfo, ISocialUser, ISocialUsersFolderPlugin
from pyams_security.interfaces.base import IPrincipalInfo
from pyams_security.interfaces.names import OAUTH_PROVIDERS_VOCABULARY_NAME, \
    SOCIAL_USERS_FOLDERS_VOCABULARY_NAME
from pyams_security.principal import PrincipalInfo
from pyams_utils.adapter import ContextAdapter, adapter_config, get_annotation_adapter
from pyams_utils.factory import factory_config
from pyams_utils.registry import query_utility
from pyams_utils.request import check_request
from pyams_utils.vocabulary import vocabulary_config


__docformat__ = 'restructuredtext'


@implementer(ISocialUser)
class SocialUser(Persistent, Contained):
    """Social user persistent class"""

    user_id = FieldProperty(ISocialUser['user_id'])
    provider_name = FieldProperty(ISocialUser['provider_name'])
    username = FieldProperty(ISocialUser['username'])
    name = FieldProperty(ISocialUser['name'])
    first_name = FieldProperty(ISocialUser['first_name'])
    last_name = FieldProperty(ISocialUser['last_name'])
    nickname = FieldProperty(ISocialUser['nickname'])
    email = FieldProperty(ISocialUser['email'])
    timezone = FieldProperty(ISocialUser['timezone'])
    country = FieldProperty(ISocialUser['country'])
    city = FieldProperty(ISocialUser['city'])
    postal_code = FieldProperty(ISocialUser['postal_code'])
    locale = FieldProperty(ISocialUser['locale'])
    picture = FieldProperty(ISocialUser['picture'])
    birth_date = FieldProperty(ISocialUser['birth_date'])
    registration_date = FieldProperty(ISocialUser['registration_date'])

    @property
    def title(self):
        if self.name:
            result = self.name
        elif self.first_name:
            result = '{first} {last}'.format(self.first_name, self.last_name or '')
        elif self.username:
            result = self.username
        else:
            result = self.nickname or self.user_id
        return result

    @property
    def title_with_source(self):
        return '{title} ({provider})'.format(title=self.title,
                                             provider=self.provider_name.capitalize())


@adapter_config(context=ISocialUser, provides=IPrincipalInfo)
def social_user_principal_info_adapter(user):
    """Social user principal info adapter"""
    return PrincipalInfo(id="{0}:{1}".format(user.__parent__.prefix, user.user_id),
                         title=user.name)


@implementer(ISocialUsersFolderPlugin)
class SocialUsersFolder(Folder):
    """Social users folder"""

    prefix = FieldProperty(ISocialUsersFolderPlugin['prefix'])
    title = FieldProperty(ISocialUsersFolderPlugin['title'])
    enabled = FieldProperty(ISocialUsersFolderPlugin['enabled'])

    def get_principal(self, principal_id, info=True):
        if not self.enabled:
            return None
        if not principal_id.startswith(self.prefix + ':'):
            return None
        prefix, login = principal_id.split(':', 1)
        user = self.get(login)
        if user is not None:
            if info:
                return PrincipalInfo(id='{prefix}:{user_id}'.format(prefix=self.prefix,
                                                                    user_id=user.user_id),
                                     title=user.title)
            else:
                return user

    def get_all_principals(self, principal_id):
        if not self.enabled:
            return set()
        if self.get_principal(principal_id) is not None:
            return {principal_id}
        return set()

    def find_principals(self, query):
        if not self.enabled:
            raise StopIteration
        # TODO: use inner text catalog for more efficient search?
        if not query:
            return None
        query = query.lower()
        for user in self.values():
            if (query == user.user_id or
                    query in (user.name or '').lower() or
                    query in (user.email or '').lower()):
                yield PrincipalInfo(id='{0}:{1}'.format(self.prefix, user.user_id),
                                    title=user.title_with_source)

    def get_search_results(self, data):
        # TODO: use inner text catalog for more efficient search?
        query = data.get('query')
        if not query:
            return ()
        query = query.lower()
        for user in self.values():
            if (query == user.user_id or
                    query in (user.name or '').lower() or
                    query in (user.email or '').lower()):
                yield user


@vocabulary_config(name=SOCIAL_USERS_FOLDERS_VOCABULARY_NAME)
class SocialUsersFolderVocabulary(SimpleVocabulary):
    """'PyAMS users folders' vocabulary"""

    def __init__(self, *args, **kwargs):
        terms = []
        manager = query_utility(ISecurityManager)
        if manager is not None:
            for name, plugin in manager.items():
                if ISocialUsersFolderPlugin.providedBy(plugin):
                    terms.append(SimpleTerm(name, title=plugin.title))
        super(SocialUsersFolderVocabulary, self).__init__(terms)


@subscriber(IAuthenticatedPrincipalEvent, plugin_selector=ISocialUsersFolderPlugin)
def handle_authenticated_principal(event):
    """Handle authenticated social principal"""
    manager = query_utility(ISecurityManager)
    social_folder = manager.get(manager.social_users_folder)
    if social_folder is not None:
        infos = event.infos
        if not (infos and
                'provider_name' in infos and
                'user' in infos):
            return
        user = infos['user']
        principal_id = event.principal_id
        if principal_id not in social_folder:
            social_user = SocialUser()
            check_request().registry.notify(ObjectCreatedEvent(social_user))
            social_user.user_id = principal_id
            social_user.provider_name = infos['provider_name']
            social_user.username = user.username
            social_user.name = user.name
            social_user.first_name = user.first_name
            social_user.last_name = user.last_name
            social_user.nickname = user.nickname
            social_user.email = user.email
            social_user.timezone = str(user.timezone)
            social_user.country = user.country
            social_user.city = user.city
            social_user.postal_code = user.postal_code
            social_user.locale = user.locale
            social_user.picture = user.picture
            if isinstance(user.birth_date, datetime):
                social_user.birth_date = user.birth_date
            social_user.registration_date = datetime.utcnow()
            social_folder[principal_id] = social_user


#
# OAuth providers configuration
#

@implementer(ISocialLoginProviderInfo)
class SocialLoginProviderInfo:
    """Social login provider info"""

    name = FieldProperty(ISocialLoginProviderInfo['name'])
    provider = None
    icon_class = FieldProperty(ISocialLoginProviderInfo['icon_class'])
    icon_filename = FieldProperty(ISocialLoginProviderInfo['icon_filename'])
    scope = FieldProperty(ISocialLoginProviderInfo['scope'])

    def __init__(self, name, provider, **kwargs):
        self.name = name
        self.provider = provider
        for k, v in kwargs.items():
            setattr(self, k, v)


PROVIDERS_INFO = {
    'behance': SocialLoginProviderInfo(name=oauth2.Behance.__name__,
                                       provider=oauth2.Behance,
                                       icon_class='fa fa-fw fa-behance-square',
                                       icon_filename='behance.ico',
                                       scope=oauth2.Behance.user_info_scope),
    'bitbucket': SocialLoginProviderInfo(name=oauth1.Bitbucket.__name__,
                                         provider=oauth1.Bitbucket,
                                         icon_class='fa fa-fw fa-bitbucket',
                                         icon_filename='bitbucket.ico'),
    'bitly': SocialLoginProviderInfo(name=oauth2.Bitly.__name__,
                                     provider=oauth2.Bitly,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='bitly.ico',
                                     scope=oauth2.Bitly.user_info_scope),
    'cosm': SocialLoginProviderInfo(name=oauth2.Cosm.__name__,
                                    provider=oauth2.Cosm,
                                    icon_class='fa fa-fw fa-share-alt',
                                    icon_filename='cosm.ico',
                                    scope=oauth2.Cosm.user_info_scope),
    'devianart': SocialLoginProviderInfo(name=oauth2.DeviantART.__name__,
                                         provider=oauth2.DeviantART,
                                         icon_class='fa fa-fw fa-deviantart',
                                         icon_filename='deviantart.ico',
                                         scope=oauth2.DeviantART.user_info_scope),
    'facebook': SocialLoginProviderInfo(name=oauth2.Facebook.__name__,
                                        provider=oauth2.Facebook,
                                        icon_class='fa fa-fw fa-facebook-square',
                                        icon_filename='facebook.ico',
                                        scope=oauth2.Facebook.user_info_scope),
    'foursquare': SocialLoginProviderInfo(name=oauth2.Foursquare.__name__,
                                          provider=oauth2.Foursquare,
                                          icon_class='fa fa-fw fa-foursquare',
                                          icon_filename='foursquare.ico',
                                          scope=oauth2.Foursquare.user_info_scope),
    'flickr': SocialLoginProviderInfo(name=oauth1.Flickr.__name__,
                                      provider=oauth1.Flickr,
                                      icon_class='fa fa-fw fa-flickr',
                                      icon_filename='flickr.ico'),
    'github': SocialLoginProviderInfo(name=oauth2.GitHub.__name__,
                                      provider=oauth2.GitHub,
                                      icon_class='fa fa-fw fa-github',
                                      icon_filename='github.ico',
                                      scope=oauth2.GitHub.user_info_scope),
    'google': SocialLoginProviderInfo(name=oauth2.Google.__name__,
                                      provider=oauth2.Google,
                                      icon_class='fa fa-fw fa-google-plus',
                                      icon_filename='google.ico',
                                      scope=oauth2.Google.user_info_scope),
    'linkedin': SocialLoginProviderInfo(name=oauth2.LinkedIn.__name__,
                                        provider=oauth2.LinkedIn,
                                        icon_class='fa fa-fw fa-linkedin-square',
                                        icon_filename='linkedin.ico',
                                        scope=oauth2.LinkedIn.user_info_scope),
    'meetup': SocialLoginProviderInfo(name=oauth1.Meetup.__name__,
                                      provider=oauth1.Meetup,
                                      icon_class='fa fa-fw fa-share-alt',
                                      icon_filename='meetup.ico'),
    'paypal': SocialLoginProviderInfo(name=oauth2.PayPal.__name__,
                                      provider=oauth2.PayPal,
                                      icon_class='fa fa-fw fa-paypal',
                                      icon_filename='paypal.ico',
                                      scope=oauth2.PayPal.user_info_scope),
    'plurk': SocialLoginProviderInfo(name=oauth1.Plurk.__name__,
                                     provider=oauth1.Plurk,
                                     icon_class='fa fa-fw fa-share-alt',
                                     icon_filename='plurk.ico'),
    'reddit': SocialLoginProviderInfo(name=oauth2.Reddit.__name__,
                                      provider=oauth2.Reddit,
                                      icon_class='fa fa-fw fa-reddit',
                                      icon_filename='reddit.ico',
                                      scope=oauth2.Reddit.user_info_scope),
    'twitter': SocialLoginProviderInfo(name=oauth1.Twitter.__name__,
                                       provider=oauth1.Twitter,
                                       icon_class='fa fa-fw fa-twitter',
                                       icon_filename='twitter.ico'),
    'tumblr': SocialLoginProviderInfo(name=oauth1.Tumblr.__name__,
                                      provider=oauth1.Tumblr,
                                      icon_class='fa fa-fw fa-tumblr-square',
                                      icon_filename='tumblr.ico'),
    'ubuntuone': SocialLoginProviderInfo(name=oauth1.UbuntuOne.__name__,
                                         provider=oauth1.UbuntuOne,
                                         icon_class='fa fa-fw fa-share-alt',
                                         icon_filename='ubuntuone.ico'),
    'viadeo': SocialLoginProviderInfo(name=oauth2.Viadeo.__name__,
                                      provider=oauth2.Viadeo,
                                      icon_class='fa fa-fw fa-share-alt',
                                      icon_filename='viadeo.ico',
                                      scope=oauth2.Viadeo.user_info_scope),
    'vimeo': SocialLoginProviderInfo(name=oauth1.Vimeo.__name__,
                                     provider=oauth1.Vimeo,
                                     icon_class='fa fa-fw fa-vimeo-square',
                                     icon_filename='vimeo.ico'),
    'vk': SocialLoginProviderInfo(name=oauth2.VK.__name__,
                                  provider=oauth2.VK,
                                  icon_class='fa fa-fw fa-vk',
                                  icon_filename='vk.ico',
                                  scope=oauth2.VK.user_info_scope),
    'windowlive': SocialLoginProviderInfo(name=oauth2.WindowsLive.__name__,
                                          provider=oauth2.WindowsLive,
                                          icon_class='fa fa-fw fa-windows',
                                          icon_filename='windows_live.ico',
                                          scope=oauth2.WindowsLive.user_info_scope),
    'xero': SocialLoginProviderInfo(name=oauth1.Xero.__name__,
                                    provider=oauth1.Xero,
                                    icon_class='fa fa-fw fa-share-alt',
                                    icon_filename='xero.ico'),
    'xing': SocialLoginProviderInfo(name=oauth1.Xing.__name__,
                                    provider=oauth1.Xing,
                                    icon_class='fa fa-fw fa-xing',
                                    icon_filename='xing.ico'),
    'yahoo': SocialLoginProviderInfo(name=oauth1.Yahoo.__name__,
                                     provider=oauth1.Yahoo,
                                     icon_class='fa fa-fw fa-yahoo',
                                     icon_filename='yahoo.ico'),
    'yammer': SocialLoginProviderInfo(name=oauth2.Yammer.__name__,
                                      provider=oauth2.Yammer,
                                      icon_class='fa fa-fw fa-share-alt',
                                      icon_filename='yammer.ico',
                                      scope=oauth2.Yammer.user_info_scope),
    'yandex': SocialLoginProviderInfo(name=oauth2.Yandex.__name__,
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

    def __init__(self, *args, **kwargs):
        terms = []
        for key, provider in PROVIDERS_INFO.items():
            terms.append(SimpleTerm(key, title=provider.name))
        terms.sort(key=lambda x: x.title)
        super(OAuthProvidersVocabulary, self).__init__(terms)


@factory_config(ISocialLoginConfiguration)
class SocialLoginConfiguration(Folder):
    """Social login configuration"""

    def get_oauth_configuration(self):
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


SOCIAL_LOGIN_CONFIGURATION_KEY = 'pyams_security.plugin.social'


@adapter_config(context=ISecurityManager, provides=ISocialLoginConfiguration)
def social_login_configuration_adapter(context):
    """Social login configuration adapter"""
    return get_annotation_adapter(context, SOCIAL_LOGIN_CONFIGURATION_KEY,
                                  ISocialLoginConfiguration,
                                  name='++social-configuration++')


@adapter_config(name='social-configuration', context=ISecurityManager, provides=ITraversable)
class SecurityManagerSocialTraverser(ContextAdapter):
    """++social-configuration++ namespace traverser"""

    def traverse(self, name, furtherpath=None):
        return ISocialLoginConfiguration(self.context)


@implementer(ISocialLoginProviderConnection)
class SocialLoginProviderConnection(Persistent):
    """Social login provider connection"""

    provider_name = FieldProperty(ISocialLoginProviderConnection['provider_name'])
    provider_id = FieldProperty(ISocialLoginProviderConnection['provider_id'])
    consumer_key = FieldProperty(ISocialLoginProviderConnection['consumer_key'])
    consumer_secret = FieldProperty(ISocialLoginProviderConnection['consumer_secret'])

    def get_configuration(self):
        return get_provider_info(self.provider_name)
