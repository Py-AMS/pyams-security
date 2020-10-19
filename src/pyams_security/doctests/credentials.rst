
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
authorization token, so that credentials are not always reauthenticated on every request.
