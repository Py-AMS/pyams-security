Changelog
=========

2.3.1
-----
 - updated translations

2.3.0
-----
 - allow case-insensitive local user login

2.2.1
-----
 - added support for custom attributes in roles

2.2.0
-----
 - added marker interface to handle unknown or missing principals
 - added argument to security manager authentication method to get plugins instance
   instead of plugin name

2.1.2
-----
 - renamed UnknownPrincipal class to avoid strange pickle behaviour...

2.1.1
-----
 - optimized principal getter helper function
 - moved PyAMS_utils finder helper to new module

2.1.0
-----
 - "forbidden" permission is not granted automatically to system manager automatically anymore;
   an optional configuration setting must be used to grant this permission

2.0.1
-----
 - updated Buildout configuration

2.0.0
-----
 - migrated to Pyramid 2.0
 - added interface and adapter to get user roles
 - added REST API authentication checker

1.11.2
------
 - renamed settings parameter used to disable default security policy on site root

1.11.1
------
 - updated doctests
 - added support for Python 3.11

1.11.0
------
 - added support for user registration
 - moved open registration settings to PyAMS_security_views package

1.10.6
------
 - updated CORS requests handler
 - use f-strings in logger output

1.10.5
------
 - added constant to set unchanged password value

1.10.4
------
 - added allowed methods argument to CORS requests handler
 - rollback on Gitlab-CI test coverage report integration

1.10.3
------
 - added Gitlab-CI test coverage report

1.10.2
------
 - added custom CORS requests handler adapter

1.10.1
------
 - updated Gitlab-CI configuration

1.10.0
------
 - added REST services configuration and validators to handle CORS requests

1.9.0
-----
 - moved security plugins interfaces to dedicated module
 - added support for Python 3.10

1.8.4
-----
 - added method to security manager to get a raw principal, bypassing cache

1.8.3
-----
 - updated translations

1.8.2
-----
 - reStructuredText formatting error...

1.8.1
-----
 - added constant for unknown principal ID
 - added constants for principal and group ID formatters

1.8.0
-----
 - added attribute to security manager to show link in home page

1.7.1
-----
 - added strings constants for plug-ins labels

1.7.0
-----
 - added ProtectedViewObjectMixin, to be used as base for any object using dynamic
   *permission* property
 - added "action" argument to "get_edit_permission()" function; this allows to register
   custom adapters to *IViewContextPermissionChecker* with this name, to be able to check
   edit permissions for custom actions
 - added ISecurityContext interface

1.6.2
-----
 - renamed 'skin' module to 'api'

1.6.1
-----
 - correction in Gitlab-CI Pylint task

1.6.0
-----
 - removed support for Python < 3.7
 - added custom password encoders
 - updated doctests

1.5.5
-----
 - updated Gitlab-CI configuration

1.5.4
-----
 - updated Gitlab-CI configuration

1.5.3
-----
 - added wheels to Buildout configuration

1.5.2
-----
 - updated Gitlab-CI configuration for last Python versions

1.5.1
-----
 - updated doctests

1.5.0
-----
 - added ISecurityManager factory configuration
 - removed Travis-CI configuration

1.4.0
-----
 - added config.upgrade_role function, to be able to add permissions to an existing role
 - updated default site roles
 - updated doctests

1.3.1
-----
 - updated security manager interface to add registered credentials plug-ins names

1.3.0
-----
 - added argument in "find_principals" methods to only allow exact match

1.2.1
-----
 - use updated WSGI decorator to prevent storage of null values into request environment

1.2.0
-----
 - updated roles management; this will allow to extend supported roles of a given class just
   by adding adapters, without modifying the original class
 - moved PyAMS security policy to dedicated module
 - added registration of standard roles and security policy
 - add factories registration in default security plug-ins
 - updated users registration process
 - updated adapter_config decorator arguments
 - updated doctests

1.1.3
-----
 - small updates in policy management of *authenticated_user_id*

1.1.2
-----
 - updated doctests with configured cache

1.1.1
-----
 - removed dependency on *pyams_auth_http* package

1.1.0
-----
 - moved authentication plug-ins to dedicated packages (see pyams_auth_http, pyams_auth_jwt...)
 - moved PyAMS authentication policy to dedicated module
 - handle ConnectionStateError in authentication policy
 - updated doctests

1.0.5
-----
 - simple version switch to avoid mismatch in Buildout configuration file...  :(

1.0.4
-----
 - code cleanup

1.0.3
-----
 - handle ConnectionStateError in JWT authentication plug-in
 - updated doctests

1.0.2
-----
 - added support for HS512 and RS512 JWT encryption protocols

1.0.1
-----
 - updated imports in include file for tests integration

1.0.0
-----
 - initial release
