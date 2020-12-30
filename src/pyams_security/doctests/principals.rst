
================
PyAMS principals
================

PyAMS security manager offers a multi-sources authentication machanism: you can define several
sources of authentication; on login, all sources are checked until one of them accept to
authenticate with given credentials; if none of them accepts given credentials, authentication
fails!

Principals which are returned by an authentication plug-in are declared by two elements:
 - a prefix, which is defined by the plug-in into which the principal was authenticated
   ("users" or "ldap", for example)
 - an ID, which may be unique for the given plug-in ("admin", for example).

These two elements form the "principal ID", made of the two elements separated by a colon, like
in "users:admin".

Generally speaking, authentication is done throught a login form, which is handling all the
authentication process, and is retrieving all principal information from security manager; but
when dealing with HTTP authentication, the incoming request have to provide the complete
principal ID, including the prefix; as HTTP authentication RFC doesn't allow to use colons
in username, you can put the prefix between brackets, followed by an optional point, like in
"{users}.admin".

You can also use a plugin API (like the JWT authentication plugin) to get an authentication
token which will be used in every request after authentication.

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> from pyramid.threadlocal import manager
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_mail import includeme as include_mail
    >>> include_mail(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyramid.threadlocal import manager
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))
    >>> manager.push({'request': request, 'registry': config.registry})

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.policy import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False)
    >>> config.set_authentication_policy(policy)

Some tests will require a configured cache:

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})
    >>> cache_regions.update({'long': {'type': 'memory', 'expire': 0}})

Let's start with a simple local user:

    >>> from pyams_security.interfaces import ISecurityManager
    >>> from pyams_utils.registry import get_utility
    >>> sm = get_utility(ISecurityManager)
    >>> sm
    <pyams_security.utility.SecurityManager object at 0x...>

    >>> from pyams_security.interfaces.notification import INotificationSettings
    >>> settings = INotificationSettings(sm)
    >>> settings.enable_notifications = True
    >>> settings.mailer = 'mailer'
    >>> mailer = settings.get_mailer()
    >>> mailer
    <...DummyMailer object at 0x...>


Principals
----------

Principals are simple objects providing the IPrincipalInfo interface; a principal
in it's minimum form is only defined by an ID and a title. A principal ID should be globally
unique, and contains a prefix which is defined by the security plug-in from which the principal
information was extraced:

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> from pyramid.threadlocal import manager
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from pyams_utils import includeme as include_utils
    >>> include_utils(config)
    >>> from pyams_mail import includeme as include_mail
    >>> include_mail(config)
    >>> from pyams_site import includeme as include_site
    >>> include_site(config)
    >>> from pyams_catalog import includeme as include_catalog
    >>> include_catalog(config)
    >>> from pyams_file import includeme as include_file
    >>> include_file(config)
    >>> from pyams_security import includeme as include_security
    >>> include_security(config)

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.policy import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False)
    >>> config.set_authentication_policy(policy)

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS catalog to generation 1...
    Upgrading PyAMS file to generation 3...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyramid.threadlocal import manager
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))
    >>> manager.push({'request': request, 'registry': config.registry})

Let's start with a simple local user:

    >>> from pyams_security.interfaces import ISecurityManager
    >>> from pyams_utils.registry import get_utility
    >>> sm = get_utility(ISecurityManager)
    >>> sm
    <pyams_security.utility.SecurityManager object at 0x...>

    >>> from pyams_security.interfaces.notification import INotificationSettings
    >>> settings = INotificationSettings(sm)
    >>> settings.enable_notifications = True
    >>> settings.mailer = 'mailer'
    >>> mailer = settings.get_mailer()
    >>> mailer
    <...DummyMailer object at 0x...>


System principals
-----------------

Beyond system principals provided by Pyramid, PyAMS allows to create so called "admin principals";
these are administration accounts, which are created automatically on first database upgrade!

Two accounts are created on upgrade: a "normal" account called "admin" (with default password
"admin"), and a "service" account called "internal"; the later one is used to handle
internal administration tasks.

    >>> from pyams_security.interfaces import ADMIN_USER_NAME, INTERNAL_USER_NAME
    >>> admin = sm[ADMIN_USER_NAME]
    >>> admin.__name__
    '__system__'
    >>> admin.login
    'admin'
    >>> admin.title
    'System manager authentication'
    >>> admin.password
    b'{SSHA}...'
    >>> admin.prefix
    'system'

    >>> internal = sm[INTERNAL_USER_NAME]
    >>> internal.__name__
    '__internal__'
    >>> internal.login
    'internal'
    >>> internal.title
    'internal service'
    >>> internal.password is None
    True
    >>> internal.prefix
    'system'

Setting admin account password to an empty value prevents login with this account!

    >>> from pyams_security.credential import Credentials
    >>> request = DummyRequest()
    >>> creds = Credentials(prefix='http', id='system:internal', login='internal', password=None)
    >>> internal.authenticate(creds, request) is None
    True


Authenticating principals
-------------------------

Authentication plug-ins extract credentials from request and returns them in an object
implementing ICredentials interface; attributes contained into a *Credentials* instance are
added by the plug-in which extracted these credentials, and can vary from a plugin to another:

    >>> from pyams_security.credential import Credentials
    >>> creds = Credentials(prefix='http', id='system:admin', login='admin', password='admin')
    >>> creds
    <...Credentials object at 0x...>
    >>> creds.prefix
    'http'
    >>> creds.id
    'system:admin'
    >>> creds.attributes['login']
    'admin'
    >>> creds.attributes['password']
    'admin'

    >>> principal_id = admin.authenticate(creds, request)
    >>> principal_id
    'system:admin'
    >>> principal = admin.get_principal(principal_id)
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> admin.get_all_principals(principal_id)
    {'system:admin'}

Authentication with bad credentials should fail by returning a None value: it's also common to
have wrong authentication access or exceptions with custom logins or password, so we have to
check for them:

    >>> req2 = new_test_request('{system}.admin', 'admin:bad', registry=config.registry)
    >>> creds2 = Credentials(prefix='http', id='admin:bad', login='admin', password='admin')
    >>> creds2
    <pyams_security.credential.Credentials object at 0x...>

    >>> admin.authenticate(creds2, req2) is None
    False


Alternate principals
--------------------

An authenticated request have a principal associated with it, which is matching a user entry in
an internal or external users database. But a principal can be associated with other ones: local
or LDAP groups to which the user is associated, are all principals which are granted
to the current request; if roles are granted to a principal in a given context, all roles
associated to the principal, directly or indirectly (via groups for example), also become new
principals which are granted to the request.

Some system principals also exist, for example "{Everyone}" or "{Authenticated}", to identify
principals associated with a given request:

    >>> request = DummyRequest()
    >>> policy.effective_principals(request)
    {'system.Everyone'}

    >>> from zope.interface import implementer
    >>> from pyams_security.interfaces import ICredentialsPlugin
    >>> from pyams_security.credential import Credentials

    >>> @implementer(ICredentialsPlugin)
    ... class FakeCredentialsPlugin:
    ...
    ...     title = "Fake credentials plugin"
    ...     prefix = 'fake'
    ...     enabled = True
    ...
    ...     def extract_credentials(self, request):
    ...         login = request.environ.get('login')
    ...         password = request.environ.get('passwd')
    ...         if login and password:
    ...             return Credentials(self.prefix, login, login=login, password=password)

    >>> plugin = FakeCredentialsPlugin()
    >>> config.registry.registerUtility(plugin, ICredentialsPlugin, name='fake')
    >>> plugin in sm.credentials_plugins
    True

    >>> request = DummyRequest()
    >>> request.environ.update({'login': 'system:admin', 'passwd': 'bad'})
    >>> request.environ.update({'doctest': True})
    >>> policy.authenticated_userid(request)
    'system:admin'
    >>> sorted(policy.effective_principals(request))
    ['system.Authenticated', 'system.Everyone', 'system:admin']

    >>> request = DummyRequest()
    >>> request.environ.update({'login': 'system:admin', 'passwd': 'admin'})
    >>> policy.authenticated_userid(request)
    'system:admin'
    >>> sorted(policy.effective_principals(request))
    ['system.Authenticated', 'system.Everyone', 'system:admin']

As you can see here, the policy "authenticated_userid" doesn't means that the request was
correctly authenticated, but only that the given credentials are matching an existing principal.

Administration principals are also directory plug-ins, so they can provide results
when looking for principals:

    >>> admin.get_principal('system:admin', info=False) is admin
    True
    >>> admin.get_principal('system:admin')
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> admin.get_principal('system:missing', info=False) is None
    True

    >>> list(admin.find_principals(''))
    []
    >>> list(admin.find_principals('admin'))
    [<pyams_security.principal.PrincipalInfo object at 0x...>]
    >>> list(admin.find_principals('admin', exact_match=True))
    [<pyams_security.principal.PrincipalInfo object at 0x...>]


Searching principals
--------------------

Authentication plugins which implement the IDirectoryPlugin interface can be used to search
principals; these can include local users, local groups as well as LDAP principals or users
which were registered using an OAuth authentication provider.

As any directory plug-in, admin principal can respond to search queries:

    >>> [principal.id for principal in admin.find_principals('admin')]
    ['system:admin']

As any security plug-in, an admin principal can be disabled; a disabled plug-in can't authenticate
a request or provide principal info:

    >>> admin.enabled = False
    >>> admin.enabled
    False
    >>> admin.authenticate(creds, request) is None
    True
    >>> admin.get_principal(principal_id) is None
    True
    >>> admin.get_all_principals(principal_id)
    set()

We will reactivate admin user for the rest of the test:

    >>> admin.enabled = True

A generic utility function is available to get principal of a given request:

    >>> from pyams_security.utility import get_principal

    >>> request = DummyRequest()
    >>> request.environ.update({'login': 'system:admin', 'passwd': 'admin'})
    >>> principal = get_principal(request)
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>

    >>> request = DummyRequest()
    >>> principal2 = get_principal(request)
    >>> principal2
    <pyams_security.principal.UnknownPrincipal object at 0x...>
    >>> principal2.title
    '< unknown principal >'

    >>> principal3 = get_principal(request, 'users:user1')
    >>> principal3
    <pyams_security.principal.MissingPrincipal object at 0x...>
    >>> principal3.title
    'MissingPrincipal: users:user1'
    >>> principal3 is principal
    False
    >>> principal3 == principal
    False


Using principal annotations
---------------------------

As principals are volatile objects, an IPrincipalAnnotationUtility can be used to store
principals related information; an IPrincipalAnnotationUtility is registered automatically
on site upgrade:

    >>> from zope.principalannotation.interfaces import IPrincipalAnnotationUtility
    >>> get_utility(IPrincipalAnnotationUtility)
    <zope.principalannotation.utility.PrincipalAnnotationUtility object at 0x...>

    >>> from zope.annotation.interfaces import IAnnotations
    >>> IAnnotations(principal)
    <zope.principalannotation.utility.Annotations object at 0x...>


Other principal features
------------------------

Principals can be compared by their ID, and used as mapping keys:

    >>> request = DummyRequest()
    >>> request.environ.update({'login': 'system:admin', 'passwd': 'admin'})
    >>> principal = get_principal(request)
    >>> principal3 = get_principal(request)

    >>> principal is principal3
    False
    >>> principal == principal3
    True

    >>> values = {principal: True}
    >>> values
    {<pyams_security.principal.PrincipalInfo object at 0x...>: True}


Tests cleanup:

    >>> manager.clear()
    >>> tearDown()
