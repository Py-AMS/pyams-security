==========================================
Managing users with PyAMS security package
==========================================

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
    >>> request = new_test_request('admin', 'admin')

    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS catalog to generation 1...
    Upgrading PyAMS file to generation 3...
    Upgrading PyAMS security to generation 2...

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyramid.threadlocal import manager
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))

    >>> from pyams_security.interfaces import ISecurityManager
    >>> from pyams_utils.registry import get_utility
    >>> sm = get_utility(ISecurityManager)


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

    >>> sm.get_plugin('users') is folder
    True

    >>> folder.enabled = False
    >>> folder.get_principal('users:user1') is None
    True
    >>> folder.enabled = True

We can now create a local user and store it into this users folder; but we must register password
managers first:

    >>> from pyams_security.plugin.userfolder import LocalUser
    >>> user1 = LocalUser()
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
    >>> from pyams_security.plugin.userfolder import notify_user_activation
    >>> folder.check_login('')
    False
    >>> folder.check_login(user1.login)
    True
    >>> folder[user1.login] = user1

Please note that there is no absolute need to use user's login as user's key in folder, but it
can be a common way to store them!

If a new user is not created "activated", a notification message is sent to the given user; this
message contains a link which will allow this user to confirm the validity of it's mail address
and activate he's account:

    >>> from pyams_security.interfaces.notification import INotificationSettings
    >>> settings = INotificationSettings(sm)
    >>> settings.mailer = 'mailer'
    >>> settings.enable_notifications = True
    >>> mailer = settings.get_mailer()
    >>> mailer
    <pyramid_mailer.mailer.DummyMailer object at 0x...>

    >>> from pyramid_chameleon.zpt import renderer_factory
    >>> config.add_renderer('.pt', renderer_factory)

    >>> notify_user_activation(user1)
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

Let's start to activate our account with an invalid hash:

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

    >>> from pyams_security.interfaces.base import IPrincipalInfo
    >>> IPrincipalInfo(user1)
    <pyams_security.principal.PrincipalInfo object at 0x...>


In some contexts, you can also let users register themselves on a web site using their own
provided credentials; in this case, a notification message is also sent to their email address
to provide an activation link:

    >>> user2 = LocalUser()
    >>> user2.self_registered = True
    >>> user2.login = 'user2@example.com'
    >>> user2.email = 'user2@example.com'
    >>> user2.firstname = 'Richard'
    >>> user2.lastname = 'Roe'
    >>> user2.password = 'passwd'
    >>> user2.generate_secret(notify=False)
    >>> user2.check_activation(user2.activation_hash, user2.login, user2.password)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Can't activate profile with given params!

    >>> folder[user2.login] = user2
    >>> notify_user_activation(user2)
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

If needed, it's possible to generate a new secret code for a user; this will disable it's profile
and send a new notification message; this will not modify the initial registration mode of a
user:

    >>> user2.refresh_secret()
    >>> user2.activated
    False
    >>> user2.password is None
    True
    >>> user2.self_registered
    True
    >>> user2.wait_confirmation
    True
    >>> user2.password is None
    True
    >>> 'You have registered a new account' in mailer.outbox[-1].body.data
    True


Notification settings also allows to o set a custom notification message; please note that you can
also change password manager (plain text storage can be required, for example, if you have to get
access to a user passord, but it's a huge security issue if your database is compromized!!!):

    >>> settings.registration_template = {'en': '<p>This is a custom registration message.</p>'}
    >>> user3 = LocalUser()
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
    >>> len(mailer.outbox)
    4
    >>> 'This is a custom registration message' in mailer.outbox[-1].body.data
    True

Let's also try to validate a few attributes:

    >>> user4 = LocalUser()
    >>> user4.email = 'bob'
    >>> user4.password = 'none'

    >>> from pyams_security.interfaces import ILocalUser
    >>> ILocalUser.validateInvariants(user4)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Given email address is not valid!


Let's now try to authenticate:

    >>> from pyams_security.credential import Credentials

    >>> request = new_test_request('{users}.user1', 'passwd', registry=config.registry)
    >>> creds = Credentials(prefix='http', id='users:user1', login='user1', password='passwd')

    >>> folder.enabled = False
    >>> folder.authenticate(creds, request) is None
    True

    >>> folder.enabled = True
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

    >>> folder.get_principal(user1_id, info=False)
    <pyams_security.plugin.userfolder.LocalUser object at 0x...>

    >>> folder.get_all_principals(user1_id)
    {'users:user1'}
    >>> folder.get_all_principals('users:userX')
    set()

    >>> folder.enabled = False
    >>> folder.get_all_principals(user1_id)
    set()
    >>> folder.enabled = True

    >>> [principal.id for principal in folder.find_principals('')]
    []
    >>> [principal.id for principal in folder.find_principals('joh')]
    ['users:user1']

Exact match is only successful when searching on user login:

    >>> [principal.id for principal in folder.find_principals('joh', exact_match=True)]
    []
    >>> [principal.id for principal in folder.find_principals('john', exact_match=True)]
    []
    >>> [principal.id for principal in folder.find_principals('user1', exact_match=True)]
    ['users:user1']

There is another API concerning searching, which will return users instead of principals:

    >>> list(folder.get_search_results({'query': 'john'}))
    [<...LocalUser object at ...>]
    >>> list(folder.get_search_results({'query': ''}))
    []

A vocabulary is available to select between users folders:

    >>> from pyams_security.plugin.userfolder import UsersFolderVocabulary
    >>> vocabulary = UsersFolderVocabulary()
    >>> len(vocabulary)
    1
    >>> pprint.pprint(vocabulary.by_value)
    {'users': <zope.schema.vocabulary.SimpleTerm object at 0x...>}


Principals groups
-----------------

Groups can be used to group principals together; permissions and roles can then be assigned to
all group members in a single operation:

    >>> from pyams_security.interfaces import PrincipalsAddedToGroupEvent, \
    ...                                       PrincipalsRemovedFromGroupEvent
    >>> from pyams_security.plugin.group import Group, GroupsFolder, \
    ...                                         handle_added_group, handle_added_principals, \
    ...                                         handle_removed_principals

We start by creating a local groups folder:

    >>> groups_folder = GroupsFolder()
    >>> groups_folder.prefix = 'groups'
    >>> groups_folder.title = 'Groups folder'
    >>> sm['groups'] = groups_folder
    >>> next(sm.groups_directory_plugins) is groups_folder
    True

Then we add a group to this folder; notice that we create a group which already contains
principals:

    >>> groups_folder.check_group_id('')
    False

    >>> group = Group()
    >>> group.group_id = 'group1'
    >>> group.title = 'Test group 1'
    >>> group.principals = {'users:user1'}
    >>> groups_folder.check_group_id(group.group_id)
    True
    >>> groups_folder[group.group_id] = group
    >>> handle_added_group(ObjectAddedEvent(group, groups_folder))
    >>> group.__parent__ is groups_folder
    True

    >>> group_id = '{}:{}'.format(groups_folder.prefix, group.group_id)

    >>> groups_folder.enabled = False
    >>> groups_folder.get_principal(group_id) is None
    True
    >>> groups_folder.get_all_principals(group_id)
    set()

You have to enable the group to get it's principals:

    >>> groups_folder.enabled = True
    >>> groups_folder.get_principal('groups:group2') is None
    True
    >>> groups_folder.get_principal('another_groups_folder:group1') is None
    True

    >>> groups_folder.get_principal(group_id)
    <...PrincipalInfo object at 0x...>
    >>> groups_folder.get_principal(group_id, info=False)
    <...Group object at 0x...>

    >>> groups_folder.get_all_principals(group_id)
    set()
    >>> groups_folder.get_all_principals(user1_id)
    {'groups:group1'}

If a group is initially empty, we can add principals to it:

    >>> groups_folder.groups_by_principal.get(user1_id)
    {'groups:group1'}
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

Of course, we can also remove principals from group:

    >>> super_group.principals = {'users:user2'}
    >>> handle_removed_principals(PrincipalsRemovedFromGroupEvent(super_group, super_group.principals))
    >>> sorted(groups_folder.get_all_principals('users:user1'))
    ['groups:group1']
    >>> sorted(groups_folder.get_all_principals('users:user2'))
    []

Looking for principals inside groups is possible:

    >>> sorted(groups_folder.find_principals(''))
    []
    >>> [group.id for group in groups_folder.find_principals('group')]
    ['groups:group1', 'groups:super_group']

    >>> sorted(sm.effective_principals(principal.id, request=request))
    ['groups:group1', 'users:user1']

A vocabulary is available to select groups:

    >>> from pyams_security.plugin.group import LocalGroupsVocabulary
    >>> vocabulary = LocalGroupsVocabulary()
    >>> len(vocabulary)
    2
    >>> pprint.pprint(vocabulary.by_value)
    {'groups:group1': <zope.schema.vocabulary.SimpleTerm object at 0x...>,
     'groups:super_group': <zope.schema.vocabulary.SimpleTerm object at 0x...>}


Principals searching view
-------------------------

A small AJAX view is provided to find principals; this view is typically used by input widgets
used to select principals, and returns results as JSON:

    >>> from pyams_security.skin import find_principals

    >>> search_request = DummyRequest(params={'query': ''})
    >>> pprint.pprint(find_principals(search_request))
    []

    >>> search_request = DummyRequest(params={'query': 'john'})
    >>> pprint.pprint(find_principals(search_request))
    [{'id': 'users:user1', 'text': 'John Doe <user@example.com>'}]

Of course, disabled plugins don't return any result:

    >>> groups_folder.enabled = False
    >>> folder.enabled = False

    >>> search_request = DummyRequest(params={'query': 'user'})
    >>> pprint.pprint(find_principals(search_request))
    []


Users registration
------------------

Some systems can accept that users register themselves on a system; this required a few
implementations; PyAMS_security only provides a few interfaces, it's up to you to implement
them.

You will also have to enable this auto-registration, and to select a users folder where these
principals will be stored:

    >>> from zope.interface import implementer
    >>> from pyams_security.interfaces import IUserRegistrationInfo

    >>> @implementer(IUserRegistrationInfo)
    ... class UserRegistration:
    ...     login = None
    ...     email = 'bob'
    ...     password = 'password'
    ...     confirmed_password = 'another_password'

    >>> info = UserRegistration()
    >>> IUserRegistrationInfo.validateInvariants(info)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Your email address is not valid!

    >>> info.email = 'bob@pyams.fr'
    >>> IUserRegistrationInfo.validateInvariants(info)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: You didn't confirmed your password correctly!

    >>> info.confirmed_password = info.password
    >>> IUserRegistrationInfo.validateInvariants(info)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Your password must contain at least three of these kinds of characters: lowercase letters, uppercase letters, numbers and special characters

    >>> info.password = info.confirmed_password = 'ABC1234ert_'
    >>> IUserRegistrationInfo.validateInvariants(info)


Tests cleanup:

    >>> tearDown()
