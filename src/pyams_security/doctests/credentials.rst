
============================
Extracting users credentials
============================

As explained before, PyAMS authentication policy relies on several kinds of plugins, which
are used to extract credentials from a given request, and then to authenticate these credentials
(if any) against an internal or external users database (being a local users folder, an LDAP
directory or an external OAuth authority provider).

Credentials extraction is done by plugins which are external to PyAMS_security package; some
example are PyAMS_auth_http (to extract credentials from an Authorization header),
PyAMS_auth_jwt (to generate and validate JWT tokens), PyAMS_auth_oauth (to handle authentication
based on an OAuth provider) or PyAMS_auth_form (to authenticate using a classic login form).

All credentials plugins are tested sequentially, until one of them returns accepted credentials;
if none of them is returning credentials, the request is left as "unauthenticated"; otherwise,
these credentials are checked against the users database to authenticate the request.

Some authentication mechanisms can store credentials information into a cookie or an
authorization token, so that credentials are not always re-authenticated on every request.


Internal service credentials
----------------------------

Some utilities, like tasks scheduler, can create custom requests using a specific "internal
service" principal. These requests are authenticated using a custom credentials getter:

    >>> from pyams_utils.request import check_request
    >>> from pyams_security.interfaces.names import ADMIN_USER_ID, INTERNAL_USER_ID
    >>> from pyams_security.plugin.admin import InternalUserCredentialsPlugin

    >>> plugin = InternalUserCredentialsPlugin()

    >>> request = check_request(principal_id=INTERNAL_USER_ID)
    >>> credentials = plugin.extract_credentials(request)
    >>> credentials is None
    False
    >>> credentials.prefix
    'internal'
    >>> credentials.id
    'system:internal'
    >>> credentials.attributes.get('pre_authenticated')
    True

    >>> request = check_request()
    >>> credentials = plugin.extract_credentials(request)
    >>> credentials is None
    True

    >>> request = check_request(principal_id=ADMIN_USER_ID)
    >>> credentials = plugin.extract_credentials(request)
    >>> credentials is None
    True
