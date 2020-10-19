
======================
PyAMS_security package
======================


Introduction
------------

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

The security manager can also handle several kinds of plug-ins, which are used to extract
credentials from your HTTP requests (being an HTTP "Authorization" header, an authentication
cookie, a JWT token or any other kind of authentication), and to authenticate them against
one or several users database.

Security manager is then responsible of getting the list of principals which are associated with
a request.

PyAMS also provides a custom authentication policy, which relies on this security manager to
extract granted roles and ACLs and get request permissions on a given context.
