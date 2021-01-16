
======================
PyAMS roles management
======================

Roles are a very important of PyAMS security policy: a role can also be defined as a "job" or
"function" ("manager", "contributor"...) which is assigned to users (or principals) on a
"context" object (being a site, a folder or a document, for example); a role groups a set of
permissions which are automatically granted to principals to whose the role is affected.

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
    Upgrading PyAMS security to generation 2...


Defining permissions
--------------------

A permission is an individual action which has to be defined when you have to define distinst
access levels according to roles which are granted to principals.

A permission is a very simple utility which is registered on application startup; being an action,
it is generally defined as a verb, like "View" or "Update content".

    >>> from pyams_security.permission import Permission, register_permission

    >>> view_permission = Permission(id='view', title='View', description='View public contents')
    >>> register_permission(config, view_permission)

    >>> from zope.component import queryUtility
    >>> from pyams_security.interfaces.base import IPermission

    >>> queryUtility(IPermission, name='view')
    <...Permission object at 0x...>

A vocabulary is used to provide all registered permissions:

    >>> from pyams_security.permission import PermissionsVocabulary
    >>> vocabulary = PermissionsVocabulary()
    >>> vocabulary.getTerm(view_permission.id)
    <....SimpleTerm object at 0x...>

You can also register a permission just by name; this will create and register a Permission
object automatically:

    >>> register_permission(config, 'pyams.manage_content')
    >>> manage_permission = queryUtility(IPermission, name='pyams.manage_content')
    >>> manage_permission.id
    'pyams.manage_content'


Defining roles
--------------

A role is a simple utility which is registered on application startup; it defines a set of
permissions which are "granted" to the role (several roles can share the same permission!), as
well as a set of "managers", which are other roles which can manage the role, this is to grant
or revoke this role to principals.

    >>> from pyams_security.role import Role, register_role
    >>> manager_role = Role(id='pyams.manager',
    ...                     title='Manager',
    ...                     permissions={view_permission.id, manage_permission.id})
    >>> register_role(config, manager_role)

    >>> contributor_role = Role(id='pyams.ocntributor',
    ...                         title='Contributor',
    ...                         permissions={view_permission.id},
    ...                         managers={manager_role.id})
    >>> register_role(config, contributor_role)

    >>> from pyams_security.interfaces.base import IRole
    >>> queryUtility(IRole, name=manager_role.id)
    <....Role object at 0x...>

If you try to register the same role multiple times, this will comple his permissions and
managers sets, but will not update it's other properties:

    >>> another_role = Role(id='pyams.manager',
    ...                     title='Another manager role',
    ...                     permissions={'pyams.delete_content'})
    >>> register_role(config, another_role)

    >>> sorted(queryUtility(IRole, name='pyams.manager').permissions)
    ['pyams.delete_content', 'pyams.manage_content', 'view']
    >>> sorted(queryUtility(IRole, name='pyams.manager').managers)
    []

You can also register a role by name:

    >>> register_role(config, 'pyams.system_manager')
    >>> queryUtility(IRole, name='pyams.system_manager')
    <pyams_security.role.Role object at 0x...>

You can also upgrade an existing role:

    >>> from pyams_security.role import upgrade_role
    >>> upgrade_role(config, 'pyams.system_manager',
    ...              permissions={'newPermission'}, managers={})
    >>> sorted(queryUtility(IRole, name='pyams.system_manager').permissions)
    ['newPermission']

Upgrading a non-existing role may raise an exception, except if the *required* argument is False:

    >>> upgrade_role(config, 'missing role name')
    Traceback (most recent call last):
    ...
    pyramid.exceptions.ConfigurationError: Provided role isn't registered!

    >>> upgrade_role(config, 'missing role name', required=False)


A vocabulary is used to provide all registered roles:

    >>> from pyams_security.role import RolesVocabulary
    >>> vocabulary = RolesVocabulary()
    >>> vocabulary.getTerm(manager_role.id)
    <....SimpleTerm object at 0x...>


Roles subscriber predicate
--------------------------

Some roles-related events, like "RoleGrantedEvent" or "RoleRevokedEvent", can be filtered using
a "role_selector" predicate:

    >>> from pyams_security.role import RoleSelector
    >>> selector = RoleSelector('pyams.manager', config)
    >>> selector.text()
    "role_selector = {'pyams.manager'}"

    >>> from pyams_security.interfaces import GrantedRoleEvent
    >>> event = GrantedRoleEvent(None, manager_role.id, 'admin:admin')
    >>> selector(event)
    True

    >>> event = GrantedRoleEvent(None, 'another.id', 'admin:admin')
    >>> selector(event)
    False


Tests cleanup:

    >>> tearDown()
