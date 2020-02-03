======================
PyAMS_security package
======================


Introduction
============

PyAMS security model relies on Pyramid's security model, which allows to define views with
permissions; there is no such fine grain security policy as there is in Zope.

The SecurityManager is the first component of this security model; it's a pluggable utility
which allows you to define several authentication sources, like local users but also like
LDAP directories or "social" users which will allows users to authenticate using OAuth;
you can also create groups, which can group any kind of principals together like local users,
LDAP users or groups, social users or even other groups. All these kinds of users or groups
are called "principals".

Permissions are granted to any kind of principals by using roles; a role is a set of permissions,
and also defines which other roles are allowed to "manage" this role, this is to grant or revoke
this role to principals.

All these roles are granted to principals on a "context" (which can be the root "site" object)
and, by default, all inner objects automatically "inherit" from these roles (but you can choose
to break this inheritance on any level).

The security manager can also include authentication plug-ins, which are created to extract
credentials from your HTTP requests (being an HTTP "Authorization" header, an authentication
cookie, a JWT token or any other kind of authentication).

Security manager is then responsible of getting the list of principals which are associated with
a request.

PyAMS also provides a custom authentication policy, which relies on this security manager to
extract granted roles and ACLs and get request permissions.


Principals
==========

Principals are simple objects providing the IPrincipalInfo interface; so a principal
in it's minimum form is only defined by an ID and a title. A principal ID should be globally
unique, and contains a prefix which is defined by the security plug-in into which the principal
was created:

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

    >>> from pyams_site.generations import upgrade_site
    >>> request = DummyRequest()
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS catalog to generation 1...
    Upgrading PyAMS file to generation 3...
    Upgrading PyAMS security to generation 1...

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
    <...SecurityManager object at 0x...>

    >>> from pyams_security.interfaces.notification import INotificationSettings
    >>> settings = INotificationSettings(sm)
    >>> settings.enable_notifications = True
    >>> settings.mailer = 'mailer'
    >>> mailer = settings.get_mailer()
    >>> mailer
    <...DummyMailer object at 0x...>


Identifying principals
----------------------

PyAMS offers a multi-sources authentication mechanism: you can define several sources of
authentication and, on login, all sources are checked until one of them accept given credentials
to authenticate; if none of them accepts given credentials, authentication fails!

Principals which are returned by an authentication plug-in are identified by two elements:
 - a prefix, which is defined by the plug-in into which the principal was defined ("users", for
   example);
 - an ID, which may be unique inside the given plug-in ("admin", for example).

The two elements form the principal ID, with the two elements separated by a colon: « users:admin ».

Generally speaking, authentication is done throught a login form which is handling all the
authentication process, and is retrieving all principal info from authentication plug-ins; but
when dealing with HTTP authentication, the incoming request have to provide the complete
principal ID, including the prefix; as HTTP authentication RFC doesn't allow to use colons
in username, you can put the prefix between brackets and followed by an optional point:
« {users}.admin ».


Credentials extraction
----------------------

Some security plug-ins are responsible of extracting credentials from input request.
For example, a plug-in is available to extract credentials from HTTP 'Authorization' header.

For example, when you initialize a new site, a default administrator is created with prefix
"system", login "admin", password "admin":

    >>> request = new_test_request('{system}.admin', 'admin', registry=config.registry)

    >>> from pyams_security.plugin.http import HttpBasicCredentialsPlugin
    >>> plugin = HttpBasicCredentialsPlugin()
    >>> creds = plugin.extract_credentials(request)
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

HTTP authentication methods other than 'basic' are not actually supported:

    >>> plugin.extract_credentials(new_test_request('{system}.admin', 'admin', method='digest')) is None
    True

As is extraction from requests without authorization:

    >>> from pyramid.testing import DummyRequest
    >>> plugin.extract_credentials(DummyRequest()) is None
    True


Admin principals
----------------

Let's start with a system admin user; such a user is created automatically on first site upgrade;
his login and password are defined as "admin":

    >>> from pyams_security.generations import get_admin_user
    >>> from pyams_security.interfaces import ADMIN_USER_NAME
    >>> admin = sm[ADMIN_USER_NAME]
    >>> admin.login
    'admin'
    >>> admin.title
    'System manager authentication'
    >>> admin.password
    b'{SSHA}...'
    >>> admin.prefix
    'system'

Authentication plug-ins extract credentials from request and returns them in an object
implementing ICredentials interface:

    >>> principal_id = admin.authenticate(creds, request)
    >>> principal_id
    'system:admin'
    >>> principal = admin.get_principal(principal_id)
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> admin.get_all_principals(principal_id)
    {'system:admin'}

Authentication with bad credentials should fail by returning a None value: tt's also common to
have wrong authentication access or exceptions with custom logins or password, so we have to
check for them:

    >>> req2 = new_test_request('{system}.admin', 'admin:bad', registry=config.registry)
    >>> creds2 = plugin.extract_credentials(req2)
    >>> creds2
    <pyams_security.credential.Credentials object at 0x...>

    >>> admin.authenticate(creds2, req2) is None
    True

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


A special admin principal is an internal "service"; it is enabled by default but you can disable
authentication by setting an empty password on it:

    >>> admin.enabled = True
    >>> admin.password = None
    >>> admin.authenticate(creds, request) is None
    True


Local users
-----------

A "local users folder" can be used to register principals which are "local" to your web site or
application, instead of being defined into another directory (like LDAP) or authenticated via
another protocol like OAuth or OAuth2.

    >>> from pyams_security.plugin.userfolder import UsersFolder
    >>> folder = UsersFolder()
    >>> folder.prefix = 'users'
    >>> folder.title = 'Local users folder'
    >>> folder.enabled
    True
    >>> sm['users'] = folder

We can now create a local user and store it into this users folder; but we must register password
managers first:

    >>> from pyams_security.plugin.userfolder import User
    >>> user1 = User()
    >>> user1.self_registered = False
    >>> user1.login = 'user1'
    >>> user1.email = 'user@example.com'
    >>> user1.firstname = 'John'
    >>> user1.lastname = 'Doe'
    >>> sorted(user1.to_dict().items())
    [('company_name', None), ('email', 'user@example.com'), ('firstname', 'John'), ('lastname', 'Doe'), ('login', 'user1'), ('title', 'John Doe')]

User password is encoded, using SSHA by default:

    >>> user1.password = 'passwd'
    >>> user1.password
    b'{SSHA}...'
    >>> user1.check_password('passwd')
    False

Why can't I check user password? Because a local user has to be activated! This can be done on
user creation, or by providing an "activation" link which will allow to verify that the given
email address is active:

    >>> user1.activated
    False
    >>> user1.self_registered
    False
    >>> user1.wait_confirmation
    True
    >>> user1.activation_hash is None
    True
    >>> user1.generate_secret()
    >>> user1.activation_secret is None
    False
    >>> user1.activation_hash is None
    False
    >>> len(user1.activation_hash)
    56
    >>> user1.activation_hash
    '...='

The hash is built from the activation secret; you can provide the hash in a email activation link
which will allow the principal to activate is account and provide a new password.

Let's now add this user to our locals users folder and try to authenticate:

    >>> from zope.lifecycleevent import ObjectAddedEvent
    >>> from pyams_security.plugin.userfolder import handle_new_local_user
    >>> folder.check_login(user1.login)
    True
    >>> folder[user1.login] = user1

Please note that there is no absolute need to use user's login as user's key in folder, but it
can be a common way to store them!

If a new user is not created "activated", a notification message is sent to the given user; this
message contains a link which will allow this user to confirm the validity of it's mail address
and activate he's account:

    >>> handle_new_local_user(ObjectAddedEvent(user1, folder))
    >>> mailer.outbox
    [<...Message object at 0x...>]
    >>> mailer.outbox[0].recipients
    ('John Doe <user@example.com>',)
    >>> mailer.outbox[0].subject
    'Please confirm registration'
    >>> 'A new account has been created for your email address' in mailer.outbox[0].body.data
    True
    >>> user1.activation_hash in mailer.outbox[0].body.data
    True

Let's start to activate our accound with an invalid hash:

    >>> bad_hash = 'THIS_IS_A_BAD_HASH'
    >>> user1.check_activation(bad_hash, 'user1', 'passwd')
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Can't activate profile with given params!

And now with the correct hash:

    >>> user1.check_activation(user1.activation_hash, 'user1', 'passwd')
    >>> user1.activated
    True
    >>> user1.wait_confirmation
    False
    >>> user1.activation_date is None
    False
    >>> user1.check_password('passwd')
    True

In some contexts, you can also let users register themselves on a web site using their own
provided credentials; in this case, a notification message is also sent to their email address
to provide an activation link:

    >>> user2 = User()
    >>> user2.login = 'user2@example.com'
    >>> user2.email = 'user2@example.com'
    >>> user2.firstname = 'Richard'
    >>> user2.lastname = 'Roe'
    >>> user2.password = 'passwd'
    >>> user2.generate_secret()

    >>> folder[user2.login] = user2
    >>> handle_new_local_user(ObjectAddedEvent(user2, folder))
    >>> len(mailer.outbox)
    2
    >>> mailer.outbox[-1].recipients
    ('Richard Roe <user2@example.com>',)
    >>> mailer.outbox[-1].subject
    'Please confirm registration'
    >>> 'You have registered a new account' in mailer.outbox[1].body.data
    True
    >>> user2.activation_hash in mailer.outbox[1].body.data
    True

    >>> user2.self_registered
    True
    >>> user2.wait_confirmation
    True
    >>> user2.activated
    False
    >>> user2.check_password('')
    False

Notification settings also allows to o set a custom notification message; please note that you can
also change password manager (plain text storage can be required, for example, if you have to get
access to a user passord, but it's a huge security issue if your database is compromized!!!):

    >>> settings.registration_template = {'en': '<p>This is a custom registration message.</p>'}
    >>> user3 = User()
    >>> user3.login = 'user3@example.com'
    >>> user3.email = 'user3@example.com'
    >>> user3.firstname = 'Jane'
    >>> user3.lastname = 'Joe'
    >>> user3.password_manager = 'Plain Text'
    >>> user3.password = 'password'
    >>> user3.password
    b'password'
    >>> user3.generate_secret()

    >>> folder[user3.login] = user3
    >>> handle_new_local_user(ObjectAddedEvent(user3, folder))
    >>> len(mailer.outbox)
    3
    >>> 'This is a custom registration message' in mailer.outbox[-1].body.data
    True

Let's now try to authenticate:

    >>> request = new_test_request('{users}.user1', 'passwd', registry=config.registry)
    >>> plugin = HttpBasicCredentialsPlugin()
    >>> creds = plugin.extract_credentials(request)
    >>> user1_id = folder.authenticate(creds, request)
    >>> user1_id
    'users:user1'

    >>> principal = folder.get_principal(user1_id)
    >>> principal
    <pyams_security.principal.PrincipalInfo object at 0x...>
    >>> principal.id
    'users:user1'
    >>> principal.title
    'John Doe'

    >>> folder.get_all_principals(user1_id)
    {'users:user1'}

    >>> [principal.id for principal in folder.find_principals('john')]
    ['users:user1']

There is another API concerning searching, which will return users instead of principals:

    >>> list(folder.get_search_results({'query': 'john'}))
    [<...User object at ...>]


Using the security manager
--------------------------

We now have a security manager with two authentication plug-ins and two principals. Let's try to
use them:

    >>> from pyams_security.interfaces import ICredentialsPlugin
    >>> config.registry.registerUtility(factory=HttpBasicCredentialsPlugin, name='http',
    ...                                 provided=ICredentialsPlugin)

    >>> from pyramid.authorization import ACLAuthorizationPolicy
    >>> config.set_authorization_policy(ACLAuthorizationPolicy())

    >>> from pyams_security.utility import PyAMSAuthenticationPolicy
    >>> policy = PyAMSAuthenticationPolicy(secret='my secret',
    ...                                    http_only=True,
    ...                                    secure=False,
    ...                                    credentials=('jwt', 'http'))
    >>> config.set_authentication_policy(policy)

    >>> request = new_test_request('user1', 'passwd', registry=config.registry)
    >>> list(sm.get_credentials_plugins(request))
    [<...JWTAuthenticationPlugin object at 0x...>, <...HttpBasicCredentialsPlugin object at 0x...>]
    >>> list(sm.get_authentication_plugins())
    [<...AdminAuthenticationPlugin object at 0x...>, <...UsersFolder object at 0x...>]
    >>> list(sm.get_directory_plugins())
    [<...AdminAuthenticationPlugin object at 0x...>, <...UsersFolder object at 0x...>]

    >>> creds = sm.extract_credentials(request)
    >>> creds
    <...Credentials object at 0x...>

    >>> sm.authenticate(creds, request)
    'users:user1'

    >>> sm.authenticated_userid(request)
    'users:user1'

Getting effective principals require a Beaker cache:

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})

The "effective_principals" method returns the list of principals associated with a given context,
which will be the request context is none is provided:

    >>> sm.effective_principals(user1_id, request)
    {'users:user1'}
    >>> sm.get_principal(user1_id)
    <...PrincipalInfo object at 0x...>
    >>> sm.get_all_principals(user1_id)
    {'users:user1'}

    >>> sm.find_principals('john')
    [<...PrincipalInfo object at 0x...>]
    >>> sm.find_principals('john')[0].id
    'users:user1'


Using OAuth authentication
--------------------------

You can activate OAuth authentication by using the Authomatic package, which provides support
for OAuth1 and OAuth2 protocols.

There are several steps required to activate this: you must first register your site or application
on at least one OAuth authentication provider, which will give you a public and a private tokens;
then, register these provider settings into the security manager, and create a "OAuth users
folder", which will be used to store properties of principals which have been authenticated with
an OAuth provider; and finally, activate these settings into the security manager:

    >>> from pyams_security.plugin.oauth import OAuthLoginProviderConnection
    >>> github_provider = OAuthLoginProviderConnection()
    >>> github_provider.provider_name = 'github'
    >>> github_provider.provider_id = 1
    >>> github_provider.consumer_key = 'this-is-my-consumer-key'
    >>> github_provider.consumer_secret = 'this-is-my-consumer-secret'

    >>> from pyams_utils.factory import register_factory
    >>> from pyams_security.interfaces import IOAuthLoginConfiguration
    >>> from pyams_security.plugin.oauth import OAuthLoginConfiguration
    >>> register_factory(IOAuthLoginConfiguration, OAuthLoginConfiguration)
    >>> login_configuration = IOAuthLoginConfiguration(sm)
    >>> login_configuration['github'] = github_provider

    >>> from pyams_security.plugin.oauth import OAuthUsersFolder
    >>> oauth_folder = OAuthUsersFolder()
    >>> oauth_folder.prefix = 'oauth'
    >>> oauth_folder.title = 'OAuth principals'
    >>> sm['oauth'] = oauth_folder

    >>> sm.oauth_users_folder = oauth_folder.__name__
    >>> sm.enable_oauth_login = True

When everything is enabled, we can accept authentication by using an external OAuth provider.

    >>> from pyams_security.skin.oauth import login as oauth_login
    >>> login_request = DummyRequest(path='/login/oauth/github', referer='/',
    ...                              matchdict={'provider_name': 'github'})
    >>> login_result = oauth_login(login_request)
    >>> login_result
    <Response at 0x... 302 Found>
    >>> login_result.location
    'https://github.com/login/oauth/authorize...client_id=this-is-my-consumer-key...'
    >>> login_result.headers.get('Set-Cookie')
    'authomatic=...; Domain=example.com; Path=; HttpOnly'

So the login request first returns a redirect response to OAuth provider URL; after correct
authentication, a new OAuth principal is created into OAuth users folder; this new principal
will be usable as any local user, to affect roles for example.


Using JWT authentication
------------------------

You can login on PyAMS application server using a JWT token, is this one is activated.
Please note that using JWT is not mandatory, you can combine JWT with other authentication
methods.

You have to set several security manager properties to use JWT:

    >>> sm.jwt_algorithm = 'HS256'
    >>> sm.jwt_secret = 'my secret'
    >>> sm.enable_jwt_login = True

    >>> from pyams_security.plugin.jwt import create_jwt_token
    >>> from pyams_security.skin.jwt import login as jwt_login

    >>> DummyRequest().unauthenticated_userid is None
    True

    >>> jwt_request = DummyRequest(method='POST', path='/login/jwt',
    ...                            params={'login': 'user1', 'password': 'passwd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = jwt_login(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'status': 'success',
     'token': 'eyJ...'}

Let's now try to use this token:

    >>> jwt_request = DummyRequest(authorization=('JWT', jwt_result['token']))
    >>> jwt_request.unauthenticated_userid
    'users:user1'
    >>> jwt_principal_id = sm.authenticated_userid(jwt_request)
    >>> jwt_principal_id
    'users:user1'

As JWT authentication don't use cookies, "remember" and "forget" authentication policies don't
return anything:

    >>> policy.authenticated_userid(jwt_request)
    'users:user1'
    >>> policy.remember(jwt_request, jwt_principal_id)
    >>> policy.forget(jwt_request)

We can try the same process using bad credentials or a bad JWT token:

    >>> jwt_request = DummyRequest(method='POST', path='/login/jwt',
    ...                            params={'login': 'user1', 'password': 'badpasswd'})
    >>> jwt_request.create_jwt_token = lambda *args, **kwargs: create_jwt_token(jwt_request, *args, **kwargs)
    >>> jwt_result = jwt_login(jwt_request)
    >>> pprint.pprint(jwt_result)
    {'message': 'Invalid credentials!', 'status': 'error'}

    >>> jwt_request = DummyRequest(authorization=('JWT', 'abc.def.ghi'), remote_addr='127.0.0.1')
    >>> jwt_principal_id = sm.authenticated_userid(jwt_request)
    >>> jwt_principal_id is None
    True
    >>> policy.authenticated_userid(jwt_request) is None
    True


Missing and unknown principals
------------------------------

There are two custom principals which are the "Unknown principal" and the "Missing principal": the
first one is used by security manager when provided principal ID is none; the second one is used
when provided principal ID is doesn't matching any active principal:

    >>> unknown = sm.get_principal(None)
    >>> unknown
    <...UnknownPrincipal object at 0x...>
    >>> unknown.id
    '__none__'
    >>> unknown.title
    '< unknown principal >'

    >>> missing = sm.get_principal('Missing ID')
    >>> missing
    <...MissingPrincipal object at 0x...>
    >>> missing.id
    'Missing ID'
    >>> missing.title
    'MissingPrincipal: Missing ID'


Principals groups
-----------------

Groups can be used to group principals together; permissions and roles can then be assigned to
all group members in a single operation:

    >>> from pyams_security.interfaces import PrincipalsAddedToGroupEvent
    >>> from pyams_security.plugin.group import Group, GroupsFolder, \
    ...                                         handle_added_group, handle_added_principals

We start by creating a local groups folder:

    >>> groups_folder = GroupsFolder()
    >>> groups_folder.prefix = 'groups'
    >>> groups_folder.title = 'Groups folder'
    >>> sm['groups'] = groups_folder

Then we add a group to this folder:

    >>> group = Group()
    >>> group.group_id = 'group1'
    >>> group.title = 'Test group 1'
    >>> groups_folder.check_group_id(group.group_id)
    True
    >>> groups_folder[group.group_id] = group
    >>> handle_added_group(ObjectAddedEvent(group, groups_folder))
    >>> group.__parent__ is groups_folder
    True

    >>> group_id = '{}:{}'.format(groups_folder.prefix, group.group_id)
    >>> groups_folder.get_principal(group_id)
    <...PrincipalInfo object at 0x...>
    >>> groups_folder.get_all_principals(group_id)
    set()
    >>> groups_folder.get_all_principals(user1_id)
    set()

Group is initialy empty, we can add principals to it:

    >>> groups_folder.groups_by_principal.get(user1_id) is None
    True
    >>> group.principals = {user1_id}
    >>> handle_added_principals(PrincipalsAddedToGroupEvent(group, group.principals))
    >>> groups_folder.get_all_principals(user1_id)
    {'groups:group1'}

A group is also seen as a principal:

    >>> sm.get_principal('groups:group1', request)
    <...PrincipalInfo object at 0x...>
    >>> groups_folder.groups_by_principal.get(user1_id)
    {'groups:group1'}

    >>> sorted(sm.get_all_principals(user1_id))
    ['groups:group1', 'users:user1']

And we can have groups of groups:

    >>> super_group = Group()
    >>> super_group.group_id = 'super_group'
    >>> super_group.title = 'Super group 1'
    >>> groups_folder.check_group_id(super_group.group_id)
    True
    >>> groups_folder[super_group.group_id] = super_group
    >>> handle_added_group(ObjectAddedEvent(super_group, groups_folder))
    >>> super_group.__parent__ is groups_folder
    True
    >>> super_group.principals = {group_id}
    >>> handle_added_principals(PrincipalsAddedToGroupEvent(super_group, super_group.principals))
    >>> sorted(groups_folder.get_all_principals(user1_id))
    ['groups:group1', 'groups:super_group']


Principals searching view
-------------------------

A small AJAX view is provided to find principals; this view is typically used by input widgets
used to select principals, and returns results as JSON:

    >>> from pyams_security.skin import find_principals
    >>> search_request = DummyRequest(params={'query': 'john'})
    >>> pprint.pprint(find_principals(search_request))
    [{'id': 'users:user1', 'text': 'John Doe <user@example.com>'}]


PyAMS authentication policy
---------------------------

The PyAMS authentication policy relies on the security manager

    >>> from zope.interface import alsoProvides
    >>> from zope.annotation import IAttributeAnnotatable
    >>> alsoProvides(request, IAttributeAnnotatable)

    >>> policy.unauthenticated_userid(request)
    'user1'
    >>> policy.authenticated_userid(request)
    'user1'

    >>> sorted(policy.effective_principals(request))
    ['system.Authenticated', 'system.Everyone', 'user1']

    >>> headers = policy.remember(request, 'users:user1')
    >>> headers[0]
    ('Set-Cookie', 'auth_ticket=...!userid_type:b64unicode; Path=/; HttpOnly; SameSite=Lax')

    >>> headers = policy.forget(request)
    >>> headers[0]
    ('Set-Cookie', 'auth_ticket=; Max-Age=0; Path=/; expires=Wed, 31-Dec-97 23:59:59 GMT; HttpOnly; SameSite=Lax')


Custom schema fields
--------------------

Custom schema fields are available to store permissions and roles names, or to grant roles
to principals; principals fields doesn't require that their associated roles have been registered,
but permissions and roles require for it to be usable:

    >>> from zope.interface import Interface, implementer
    >>> from pyams_security.schema import PermissionField, PermissionsSetField, \
    ...                                   RoleField, RolesSetField, \
    ...                                   PrincipalField, PrincipalsSetField

    >>> class IMyCustomInterface(Interface):
    ...     permission = PermissionField(title='Single permission field')
    ...     permissions_set = PermissionsSetField(title='Permissions set field')
    ...     role = RoleField(title='Single role field')
    ...     roles_set = RolesSetField(title='Roles set field')
    ...     principal = PrincipalField(title='Single principal field')
    ...     principals_set = PrincipalsSetField(title='Principals set field')

Custom properties are then available for principals:

    >>> from zope.schema.fieldproperty import FieldProperty

    >>> @implementer(IMyCustomInterface)
    ... class MyCustomContent:
    ...     permission = FieldProperty(IMyCustomInterface['permission'])
    ...     permissions_set = FieldProperty(IMyCustomInterface['permissions_set'])
    ...     role = FieldProperty(IMyCustomInterface['role'])
    ...     roles_set = FieldProperty(IMyCustomInterface['roles_set'])
    ...     principal = FieldProperty(IMyCustomInterface['principal'])
    ...     principals_set = FieldProperty(IMyCustomInterface['principals_set'])

    >>> content = MyCustomContent()
    >>> content.permission = 'view'
    Traceback (most recent call last):
    ...
    zope.schema._bootstrapinterfaces.ConstraintNotSatisfied: ('view', 'permission')

As said before, this error is due to the fact that the assigned permission hasn't been
registered:

    >>> from pyams_security.permission import Permission, register_permission
    >>> from pyams_security.role import Role, register_role

    >>> view_permission = Permission(id='view', title='View permission')
    >>> register_permission(config, view_permission)
    >>> edit_permission = Permission(id='edit', title='Edit permission')
    >>> register_permission(config, edit_permission)
    >>> admin_permission = Permission(id='admin', title='Admin permission')
    >>> register_permission(config, admin_permission)

    >>> guest_role = Role(id='guest', title='Guest role',
    ...                   permissions={view_permission.id})
    >>> register_role(config, guest_role)

Permissions and roles can then be assigned by using their ID or an object:

    >>> IMyCustomInterface['permission'].validate(edit_permission)
    >>> IMyCustomInterface['permission'].validate(edit_permission.id)
    >>> IMyCustomInterface['permission'].set(content, edit_permission)
    >>> content.permission
    'edit'
    >>> content.permission = view_permission.id
    >>> content.permission
    'view'

    >>> IMyCustomInterface['permissions_set'].validate({edit_permission})
    >>> IMyCustomInterface['permissions_set'].validate({edit_permission.id})
    >>> IMyCustomInterface['permissions_set'].set(content, {edit_permission})
    >>> content.permissions_set
    {'edit'}
    >>> content.permissions_set = {view_permission.id}
    >>> content.permissions_set
    {'view'}

    >>> IMyCustomInterface['role'].validate(guest_role)
    >>> IMyCustomInterface['role'].validate(guest_role.id)
    >>> IMyCustomInterface['role'].set(content, guest_role)
    >>> content.role
    'guest'
    >>> content.role = guest_role.id
    >>> content.role
    'guest'

    >>> IMyCustomInterface['roles_set'].validate({guest_role})
    >>> IMyCustomInterface['roles_set'].validate({guest_role.id})
    >>> IMyCustomInterface['roles_set'].set(content, {guest_role})
    >>> content.roles_set
    {'guest'}
    >>> content.roles_set = {guest_role.id}
    >>> content.roles_set
    {'guest'}

    >>> IMyCustomInterface['principal'].validate(principal)
    >>> IMyCustomInterface['principal'].validate(principal.id)
    >>> IMyCustomInterface['principal'].set(content, principal)
    >>> content.principal
    'users:user1'
    >>> content.principal = user1_id
    >>> content.principal
    'users:user1'

    >>> IMyCustomInterface['principals_set'].validate({principal})
    >>> IMyCustomInterface['principals_set'].validate({principal.id})
    >>> IMyCustomInterface['principals_set'].set(content, {principal})
    >>> content.principals_set
    {'users:user1'}
    >>> content.principals_set = {principal.id}
    >>> content.principals_set
    {'users:user1'}


Using roles
-----------

A role is a registered utility to which we assign permissions; a role is then granted to
principals in the context of an object:

    >>> admin_role = Role(id='admin_role', title='Admin role',
    ...                   permissions={admin_permission.id, edit_permission.id})
    >>> register_role(config, admin_role)
    >>> edit_role = Role(id='edit_role', title='Editor role',
    ...                   permissions={edit_permission.id},
    ...                   managers={admin_role.id})
    >>> register_role(config, edit_role)

Let's now create a context and assign roles to it; granting roles through these properties require
that the interface which is defining roles attributes inherit from IDefaultProtectionPolicy, and
that the implementation class is adaptatable to IProtectedObject; inherit from ProtectedObjectMixin
allows to get this adapter automatically:

    >>> from pyams_security.interfaces import IRoleProtectedObject
    >>> from pyams_security.schema import PrincipalsSetField

    >>> from pyams_security.interfaces import IDefaultProtectionPolicy
    >>> from pyams_security.security import ProtectedObjectMixin

    >>> class IMyContext(IDefaultProtectionPolicy):
    ...     admins = PrincipalsSetField(title='Admins list', role_id=admin_role.id)
    ...     editors = PrincipalsSetField(title='Editors list', role_id=edit_role.id)

    >>> from pyams_security.property import RolePrincipalsFieldProperty

    >>> @implementer(IMyContext)
    ... class MyContext(ProtectedObjectMixin):
    ...     __parent__ = None
    ...     admins = RolePrincipalsFieldProperty(IMyContext['admins'])
    ...     editors = RolePrincipalsFieldProperty(IMyContext['editors'])

    >>> context = MyContext()
    >>> context.admins = {user1_id}

    >>> from pyams_security.interfaces import IProtectedObject
    >>> po = IProtectedObject(context)
    >>> po.get_granted_roles()
    {'admin_role'}
    >>> po.get_roles(user1_id)
    {'admin_role'}
    >>> po.get_principals(admin_role.id)
    {'users:user1'}
    >>> sorted(po.get_permissions(user1_id))
    ['admin', 'edit']

    >>> pprint.pprint(po.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:admin_role', {...'admin'...})]

Roles are also affected to users as principals; some properties are cached into request annotations,
so all updates may not be visible during the request lifetime, that's why we create a new request
after some updates to avoid caching problems:

    >>> request = new_test_request('{users}.user1', 'passwd',
    ...                            context=context, registry=config.registry)

    >>> sorted(policy.effective_principals(request))
    ['groups:group1', 'groups:super_group', 'role:admin_role', 'system.Authenticated', 'system.Everyone', 'users:user1']

We can then change granted roles:

    >>> context.admins = {}
    >>> context.editors = {user1_id}

    >>> request = new_test_request('{users}.user1', 'passwd',
    ...                            context=context, registry=config.registry)

    >>> sorted(policy.effective_principals(request))
    ['groups:group1', 'groups:super_group', 'role:edit_role', 'system.Authenticated', 'system.Everyone', 'users:user1']

We can also remove principals from super group:

    >>> from pyams_security.interfaces import PrincipalsRemovedFromGroupEvent
    >>> from pyams_security.plugin.group import handle_removed_principals
    >>> old_principals = super_group.principals
    >>> super_group.principals = {}
    >>> handle_removed_principals(PrincipalsRemovedFromGroupEvent(super_group, old_principals))

We can also check request permissions when they were granted through roles:

    >>> request.has_permission(edit_permission.id, context=context)
    <ACLAllowed instance at ... with msg "ACLAllowed permission 'edit' via ACE ('Allow', 'role:edit_role', {'edit'}) in ACL [...] on context <...MyContext object at 0x...> for principals {...}">

We should get the same values if we grant roles by using groups instead of individual principals:

    >>> context.admins = {}
    >>> context.editors = {'groups:group1'}

    >>> request = new_test_request('{users}.user1', 'passwd',
    ...                            context=context, registry=config.registry)

    >>> sorted(policy.effective_principals(request))
    ['groups:group1', 'role:edit_role', 'system.Authenticated', 'system.Everyone', 'users:user1']

We can also check request permissions when they were granted through roles:

    >>> request.has_permission(edit_permission.id, context=context)
    <ACLAllowed instance at ... with msg "ACLAllowed permission 'edit' via ACE ('Allow', 'role:edit_role', {'edit'}) in ACL [...] on context <...MyContext object at 0x...> for principals {...}">

Let's finish by revoking role and verifying that all edit permission is not denied:

    >>> context.editors = {}

    >>> request = new_test_request('{users}.user1', 'passwd',
    ...                            context=context, registry=config.registry)

    >>> sorted(policy.effective_principals(request))
    ['groups:group1', 'system.Authenticated', 'system.Everyone', 'users:user1']

    >>> request.has_permission(edit_permission.id, context=context)
    <ACLDenied instance at ... with msg "ACLDenied permission 'edit' via ACE '<default deny>' in ACL [...] on context <...MyContext object at 0x...> for principals {...}">


Tests cleanup:

    >>> from pyams_utils.registry import set_local_registry
    >>> set_local_registry(None)
    >>> manager.clear()
    >>> tearDown()
