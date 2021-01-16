
======================
PyAMS objects security
======================

PyAMS_security package provides a few classes which can be used to handle objects security.
This includes classes to grant roles to principal, using dedicated schema fields and properties:

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

Some tests will require a configured cache:

    >>> from beaker.cache import CacheManager, cache_regions
    >>> cache = CacheManager(**{'cache.type': 'memory'})
    >>> cache_regions.update({'short': {'type': 'memory', 'expire': 0}})


Security schemas fields
-----------------------

Several schemas fields are provided to store permissions and roles. We first have to register
permissions and roles:

    >>> from pyams_security.permission import Permission, register_permission
    >>> from pyams_security.role import Role, register_role

    >>> manage_permission = Permission(id='pyams.manage_content', title='Manage',
    ...                                description='View public contents')
    >>> register_permission(config, manage_permission)
    >>> view_permission = Permission(id='pyams.view', title='View',
    ...                              description='View public contents')
    >>> register_permission(config, view_permission)

    >>> manager_role = Role(id='pyams.manager',
    ...                     title='Manager',
    ...                     permissions={view_permission.id, manage_permission.id})
    >>> register_role(config, manager_role)

    >>> designer_role = Role(id='pyams.designer',
    ...                      title='Designer',
    ...                      permissions={view_permission.id})
    >>> register_role(config, designer_role)

    >>> from pyams_security.schema import PermissionField, PermissionsSetField
    >>> from pyams_security.schema import RoleField, RolesSetField
    >>> from pyams_security.schema import PrincipalField, PrincipalsSetField

    >>> from zope.interface import implementer, Interface

    >>> class IMySchema(Interface):
    ...     permission = PermissionField(title="Permission")
    ...     permissions_set = PermissionsSetField(title="Permissions set")
    ...     role = RoleField(title="Role")
    ...     roles_set = RolesSetField(title="Roles set")
    ...     principal = PrincipalField(title="Principal")
    ...     principals_set = PrincipalsSetField(title="Principals set")

    >>> from zope.schema.fieldproperty import FieldProperty
    >>> @implementer(IMySchema)
    ... class MySchema:
    ...     permission = FieldProperty(IMySchema['permission'])
    ...     permissions_set = FieldProperty(IMySchema['permissions_set'])
    ...     role = FieldProperty(IMySchema['role'])
    ...     roles_set = FieldProperty(IMySchema['roles_set'])
    ...     principal = FieldProperty(IMySchema['principal'])
    ...     principals_set = FieldProperty(IMySchema['principals_set'])

    >>> context = MySchema()

Permissions can be set using a permission object, or a permission ID; all require a registered
permission:

    >>> IMySchema['permission'].validate(view_permission)
    >>> IMySchema['permission'].set(context, view_permission)
    >>> context.permission
    'pyams.view'
    >>> IMySchema['permissions_set'].set(context, {view_permission.id})
    >>> context.permissions_set
    {'pyams.view'}

    >>> context.permission = 'unknown'
    Traceback (most recent call last):
    ...
    zope.schema._bootstrapinterfaces.ConstraintNotSatisfied: ('unknown', 'permission')

Roles can be set using a role object, or a role ID; all require a registered role:

    >>> IMySchema['role'].validate(manager_role)
    >>> IMySchema['role'].set(context, manager_role)
    >>> context.role
    'pyams.manager'
    >>> IMySchema['roles_set'].set(context, {manager_role.id})
    >>> context.roles_set
    {'pyams.manager'}

    >>> context.role = 'unknown'
    Traceback (most recent call last):
    ...
    zope.schema._bootstrapinterfaces.ConstraintNotSatisfied: ('unknown', 'role')

There is no validation rule concerning principals, you can assign a value to a property using
an unknown principal:

    >>> from pyams_security.principal import PrincipalInfo
    >>> principal = PrincipalInfo(id='system:admin')

    >>> IMySchema['principal'].validate(principal)
    >>> IMySchema['principal'].validate('user:unknown')
    >>> IMySchema['principal'].set(context, principal)
    >>> context.principal
    'system:admin'
    >>> IMySchema['principals_set'].set(context, {principal.id})
    >>> context.principals_set
    {'system:admin'}


Protecting objects with roles
-----------------------------

You can grant roles to principals directly on an object to define ACLs; this requires a few more
work; the first step is to create an interface with principals schema fields setting roles, and
to inherit from ProtectecObjectMixin:

    >>> from pyams_security.interfaces import IContentRoles, IRolesPolicy
    >>> from pyams_security.security import ProtectedObjectMixin

    >>> class IMyProtectedClass(Interface):
    ...     """Base content interface"""

    >>> @implementer(IMyProtectedClass)
    ... class ProtectedObject(ProtectedObjectMixin):
    ...     """Protected object class"""

We are now going to create a little set of interfaces and adapters; the goal is to be able to
add roles to a given class just by adding adapters:

    >>> class IMyClassRoles(IContentRoles):
    ...     manager = PrincipalField(title="Main manager", role_id=manager_role)
    ...     managers = PrincipalsSetField(title="Managers list", role_id=manager_role)
    ...     designer = PrincipalField(title="Main designer")
    ...     designers = PrincipalsSetField(title="Designers list")

    >>> from pyams_security.property import RolePrincipalsFieldProperty

    >>> @implementer(IMyProtectedClass)
    ... class MyRolesClass:
    ...
    ...     def __init__(self, context):
    ...         self.__parent__ = context
    ...
    ...     manager = RolePrincipalsFieldProperty(IMyClassRoles['manager'])
    ...     managers = RolePrincipalsFieldProperty(IMyClassRoles['managers'])
    ...     designer = RolePrincipalsFieldProperty(IMyClassRoles['designer'],
    ...                                            role_id=designer_role)
    ...     designers = RolePrincipalsFieldProperty(IMyClassRoles['designers'],
    ...                                             role_id=designer_role)

    >>> from pyams_utils.adapter import adapter_config, ContextAdapter
    >>> from pyams_utils.testing import call_decorator

    >>> def protected_class_roles_adapter(context):
    ...     return MyRolesClass(context)

    >>> call_decorator(config, adapter_config, protected_class_roles_adapter,
    ...                required=IMyProtectedClass, provides=IMyClassRoles)

    >>> class MyProtectedClassRolesPolicy(ContextAdapter):
    ...     roles_interface = IMyClassRoles
    ...     weight = 1  # just used for ordering

    >>> call_decorator(config, adapter_config, MyProtectedClassRolesPolicy,
    ...                name='MyRoles', required=IMyProtectedClass, provides=IRolesPolicy)

    >>> protected = ProtectedObject()
    >>> protected.__acl__()
    []

    >>> roles = IMyClassRoles(protected)
    >>> roles.managers
    set()
    >>> roles.managers = {'system:admin'}
    Traceback (most recent call last):
    ...
    ValueError: Can't use role properties on object not providing IRoleProtectedObject interface!

You have to implement the IDefaultProtectionPolicy to be able to support roles:

    >>> from zope.interface import alsoProvides
    >>> from pyams_security.interfaces import IDefaultProtectionPolicy
    >>> alsoProvides(protected, IDefaultProtectionPolicy)

    >>> roles.manager = 'system:admin'
    >>> roles.manager
    {'system:admin'}
    >>> roles.managers = {'system:admin'}
    >>> roles.managers
    {'system:admin'}

Principals can be set using a set or strings:

    >>> roles.designers = None
    >>> roles.designers = 'users:unknown'
    >>> pprint.pprint(protected.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:pyams...', {'pyams...}),
     ('Allow', 'role:pyams...', {'pyams...})]


Inheriting ACls
---------------

You can inherit ACLs from parent objects:

    >>> from zope.location import Location
    >>> @implementer(IDefaultProtectionPolicy)
    ... class Child(ProtectedObject, Location):
    ...     """Child class"""

    >>> child = Child()
    >>> child.__parent__ = protected

By default, child ACLs are the same as their parent ACLs:

    >>> pprint.pprint(child.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:pyams...', {'pyams...'}),
     ('Allow', 'role:pyams...', {'pyams...'})]

But you can add custom principals and extend ACLs:

    >>> child.designers = {principal}
    >>> pprint.pprint(child.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:pyams...', {'pyams...'}),
     ('Allow', 'role:pyams...', {'pyams...'})]

You can also revoke roles from principals:

    >>> child.designers = {'users:user1'}
    >>> child.designers = {}
    >>> pprint.pprint(child.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:pyams...', {'pyams...'}),
     ('Allow', 'role:pyams...', {'pyams...'})]


Using the IProtectedObject interface
------------------------------------

You can use the IRoleProtectedObject interface directly to get more information:

    >>> from pyams_security.interfaces import IProtectedObject

    >>> protection = IProtectedObject(protected)
    >>> protection
    <pyams_security.security.RoleProtectedObject object at 0x...>

    >>> protection.get_roles(principal)
    {'pyams.manager'}

This method doesn't return inherited roles, but only roles applied locally:

    >>> IProtectedObject(child).get_roles(principal)
    set()

You can also get the list of permissions:

    >>> sorted(protection.get_permissions(principal))
    ['pyams.manage_content', 'pyams.view']

    >>> sorted(IProtectedObject(child).get_permissions(principal))
    []

This interface can also be used to grant or revoke roles:

    >>> protection.grant_role(designer_role, {principal})
    >>> sorted(roles.designers)
    ['system:admin', 'users:unknown']

    >>> protection.revoke_role(designer_role, {principal})
    >>> sorted(roles.designers)
    ['users:unknown']


Using security manager to get principals
----------------------------------------

Roles granted to a principal are seen as additional principals:

    >>> request = new_test_request('user1', 'password', context=child)
    >>> sorted(sm.effective_principals(principal.id, request=request))
    ['role:pyams.manager', 'system:admin']


Granted and denied permissions
------------------------------

On any context, you can break inheritance but also define a set of permissions which will be
granted to everyone or to any authenticated principal, or which will be denied to everyone or
to any authenticated principal:

    >>> register_permission(config, 'denied:everyone')
    >>> register_permission(config, 'granted:everyone')
    >>> register_permission(config, 'denied:authenticated')
    >>> register_permission(config, 'granted:authenticated')

    >>> child_protection = IProtectedObject(child)
    >>> child_protection.inherit_parent_security = False
    >>> child_protection.everyone_denied = {'denied:everyone'}
    >>> child_protection.everyone_granted = {'granted:everyone'}
    >>> child_protection.authenticated_denied = {'denied:authenticated'}
    >>> child_protection.authenticated_granted = {'granted:authenticated'}

    >>> pprint.pprint(child_protection.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', {'public'}),
     ('Allow', 'role:pyams...', {'pyams...'}),
     ('Allow', 'role:pyams...', {'pyams...'}),
     ('Deny', 'system.Everyone', {'denied:everyone'}),
     ('Deny', 'system.Authenticated', {'denied:authenticated'}),
     ('Allow', 'system.Authenticated', {'granted:authenticated'}),
     ('Allow', 'system.Everyone', {'granted:everyone'}),
     ('Deny',
      'system.Everyone',
      <pyramid.security.AllPermissionsList object at 0x...>)]


Getting context edit permission
-------------------------------

The "edit" permission is a permissions which is frequently required to be able to update
a "content" properties. The "get_edit_permission", which is actually used for example by
PyAMS forms management package, relies on a multi-adapter:

    >>> from pyams_security.permission import get_edit_permission

    >>> get_edit_permission(request) is None
    True

    >>> class CustomPermissionChecker:
    ...     def __init__(self, context):
    ...         pass
    ...     @property
    ...     def edit_permission(self):
    ...         return 'My permission'

    >>> from pyams_security.interfaces import IViewContextPermissionChecker
    >>> call_decorator(config, adapter_config, CustomPermissionChecker,
    ...                required=object, provides=IViewContextPermissionChecker)

    >>> get_edit_permission(request)
    'My permission'


Indexing granted roles
----------------------

It's possible to index a role-based principals schema field, to be able to get easilly the
list of objects on which a principal was granted roles:

    >>> from pyams_security.index import PrincipalsRoleIndex
    >>> index = PrincipalsRoleIndex(role_id=manager_role.id)
    >>> index.discriminate(protected, None)
    {'system:admin'}


Tests cleanup:

    >>> tearDown()
