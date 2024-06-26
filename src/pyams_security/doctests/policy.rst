
===========================
PyAMS authentication policy
===========================

PyAMS provides a custom authentication policy for Pyramid integration; this policy is used
to extract credentials from request and authenticate users, and relies on registered security
manager settings.

Associated utilities also provides support for role-based authorizations.

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from cornice import includeme as include_cornice
    >>> include_cornice(config)
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

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS catalog to generation 1...
    Upgrading PyAMS file to generation 3...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))

    >>> from pyams_security.interfaces import ISecurityManager
    >>> from pyams_utils.registry import get_utility
    >>> sm = get_utility(ISecurityManager)
    >>> sm
    <pyams_security.utility.SecurityManager object at 0x...>


The policy is generally initialized ou your main application startup script:

    >>> from pyams_security.policy import PyAMSSecurityPolicy
    >>> policy = PyAMSSecurityPolicy(secret='my secret',
    ...                              http_only=True,
    ...                              secure=False)
    >>> config.set_security_policy(policy)

The "admin" principal is created automatically on database upgrade; this first admin user is
required for first management tasks, his password ("admin") should be changed as soon as possble!!

    >>> request = new_test_request('admin', 'admin', registry=config.registry)

    >>> from pyams_security.interfaces.names import ADMIN_USER_NAME
    >>> admin = sm.get(ADMIN_USER_NAME)
    >>> admin
    <...AdminAuthenticationPlugin object at 0x...>
    >>> admin in sm.credentials_plugins
    False
    >>> admin in sm.authentication_plugins
    True
    >>> admin in sm.directory_plugins
    True


Using PyAMS security policy
---------------------------

PyAMS security policy relies on a persistent security manager utility; this manager
is a pluggable component which relies itself on registered utilities and local components
to extract credentials from requests and then authenticate these credentials.

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})
    >>> cache_regions.update({'long': {'type': 'memory', 'expire': 0}})

    >>> sm is policy.security_manager
    True
    >>> admin in policy.credentials_plugins
    False

    >>> policy.authenticated_userid(request) is None
    True
    >>> identity = request.identity
    >>> identity is None
    True

Once registered, security policy is used automatically by Pyramid requests to extract
information; to be able to extract credentials (which are actually handled by
external plug-ins), we will create a fake plug-in which will extract credentials from request
environment:

    >>> from zope.interface import implementer
    >>> from pyams_security.interfaces.plugin import ICredentialsPlugin
    >>> from pyams_security.credential import Credentials

    >>> @implementer(ICredentialsPlugin)
    ... class FakeCredentialsPlugin:
    ...     title = "Fake credentials plugin"
    ...     prefix = 'fake'
    ...     enabled = True
    ...     def extract_credentials(self, request):
    ...         login = request.environ.get('login')
    ...         password = request.environ.get('passwd')
    ...         if login and password:
    ...             return Credentials(self.prefix, login, login=login, password=password)

    >>> plugin = FakeCredentialsPlugin()
    >>> config.registry.registerUtility(plugin, ICredentialsPlugin, name='fake')

    >>> plugin in policy.credentials_plugins
    True

    >>> request = DummyRequest()
    >>> request.environ.update({'login': 'admin', 'passwd': 'admin'})

    >>> sorted(request.identity.get('principals'))
    ['system.Authenticated', 'system.Everyone', 'system:admin']

Security policy is also used when you have to remember a user's session, using cookies:

    >>> headers = policy.remember(request, 'users:user1')
    >>> headers[0]
    ('Set-Cookie', 'auth_ticket=...!userid_type:b64unicode; Domain=example.com; Path=/; HttpOnly; SameSite=Lax')

    >>> headers = policy.forget(request)
    >>> headers[0]
    ('Set-Cookie', 'auth_ticket=; Domain=example.com; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT; HttpOnly; SameSite=Lax')


Internal service identity
-------------------------

Some tasks, like scheduler ones, can be run using a specific internal user ID:

    >>> from pyramid.threadlocal import RequestContext, manager
    >>> from pyams_security.interfaces.names import INTERNAL_USER_ID
    >>> from pyams_utils.request import check_request

    >>> manager.clear()
    >>> request = check_request(registry=config.registry, principal_id=INTERNAL_USER_ID)
    >>> manager.push({'registry': config.registry, 'request': request})

    >>> identity = request.identity
    >>> identity is None
    False
    >>> identity['userid'] == INTERNAL_USER_ID
    True
    >>> sorted(identity['principals'])
    ['system.Authenticated', 'system.Everyone', 'system:internal']


Authentication plugins are available as external packages, which can be included individually
into Pyramid's application configuration; some examples are "pyams_auth_http", "pyams_auth_jwt",
"pyams_auth_oauth" or "pyams_ldap".


Test cleanup:

    >>> tearDown()
