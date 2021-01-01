
======================
PyAMS security manager
======================

PyAMS security manager is a persistent utility which is stored into the ZODB; it is pluggable,
and can handle several plug-in types, which can be used to:

 - extract credentials from an HTTP request (see ICredentialsPlugin)

 - authenticate these credentials against a user database (see IAuthenticationPlugin)

 - provide a searchable directory of users (see IDirectoryPlugin)

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

An ISecurityManager instance is created automatically on instance upgrade:

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

    >>> list(sm.keys())
    ['__internal__', '__system__']

Let's add a first security manager plugin, which a folder used to store local users:

    >>> from pyams_security.plugin.userfolder import UsersFolder
    >>> folder = UsersFolder()
    >>> folder.prefix = 'users'
    >>> folder.title = 'Local users folder'
    >>> folder.enabled
    True
    >>> sm['users'] = folder


Using the security manager
--------------------------

We now have a security manager with two authentication plug-ins and two principals. Let's try to
use them:

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.policy import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False)
    >>> config.set_authentication_policy(policy)

    >>> request = new_test_request('user1', 'passwd', registry=config.registry)
    >>> list(sm.credentials_plugins_names)
    []
    >>> list(sm.credentials_plugins)
    []
    >>> list(sm.authentication_plugins)
    [<...AdminAuthenticationPlugin object at 0x...>, <...AdminAuthenticationPlugin object at 0x...>, <...UsersFolder object at 0x...>]
    >>> list(sm.directory_plugins)
    [<...AdminAuthenticationPlugin object at 0x...>, <...AdminAuthenticationPlugin object at 0x...>, <...UsersFolder object at 0x...>]

    >>> creds = sm.extract_credentials(request)
    >>> creds is None
    True

This is normal now, as we don't have any credentials extraction plug-in in the current
configuration!

    >>> sm.authenticate(creds, request) is None
    True

    >>> sm.authenticated_userid(request) is None
    True

Getting effective principals require a Beaker cache:

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})
    >>> cache_regions.update({'long': {'type': 'memory', 'expire': 0}})

The "effective_principals" method returns the list of principals associated with a given context,
which will be the request context is none is provided:

    # >>> sm.get_principal.cache_clear()

    >>> from pyams_security.credential import Credentials

    >>> request = new_test_request('{users}.user1', 'passwd', registry=config.registry)
    >>> creds = Credentials(prefix='http', id='users:user1', login='user1', password='passwd')
    >>> user1_id = folder.authenticate(creds, request)
    >>> user1_id is None
    True

Let's create a new local user:

    >>> from pyams_security.plugin.userfolder import LocalUser
    >>> user1 = LocalUser()
    >>> user1.self_registered = False
    >>> user1.login = 'user1'
    >>> user1.email = 'user@example.com'
    >>> user1.firstname = 'John'
    >>> user1.lastname = 'Doe'
    >>> user1.password = 'passwd'
    >>> user1.activated = True
    >>> folder['user1'] = user1

    >>> user1_id = folder.authenticate(creds, request)
    >>> user1_id
    'users:user1'
    >>> sm.effective_principals(user1_id, request)
    {'users:user1'}
    >>> sm.get_principal(user1_id)
    <...PrincipalInfo object at 0x...>
    >>> sm.get_all_principals(user1_id)
    {'users:user1'}

    >>> sm.find_principals('joh')
    [<...PrincipalInfo object at 0x...>]
    >>> sm.find_principals('john')[0].id
    'users:user1'
    >>> sm.find_principals('joh', exact_match=True)
    []

Exact match is only successful on user's login:

    >>> sm.find_principals('john', exact_match=True)
    []
    >>> sm.find_principals('admin', exact_match=True)
    [<...PrincipalInfo object at 0x...>]

    >>> request = new_test_request('{users}.user1', 'passwd', registry=config.registry)


Deleting plugins
----------------

    >>> del sm['__system__']
    >>> del sm['users']
    >>> list(sm.credentials_plugins)
    []
    >>> list(sm.authentication_plugins)
    [<...AdminAuthenticationPlugin object at 0x...>]
    >>> list(sm.directory_plugins)
    [<...AdminAuthenticationPlugin object at 0x...>]


Test cleanup:

    >>> tearDown()
