======================
PyAMS_security package
======================

.. contents::


What is PyAMS?
==============

PyAMS (Pyramid Application Management Suite) is a small suite of packages written for applications
and content management with the Pyramid framework.

**PyAMS** is actually mainly used to manage web sites through content management applications (CMS,
see PyAMS_content package), but many features are generic and can be used inside any kind of web
application.

All PyAMS documentation is available on `ReadTheDocs <https://pyams.readthedocs.io>`_; source code
is available on `Gitlab <https://gitlab.com/pyams>`_ and pushed to `Github
<https://github.com/py-ams>`_.


What is PyAMS_security?
=======================

PyAMS_security is a core extension package for PyAMS which provides all base security-related
features; the package provides a custom authentication policy which is based on a custom "security
manager". This utility is a pluggable tool which is handling system users, local users and groups;
external packages are available to provide other authentication and security mechanisms, like
HTTP authentication, JWT tokens management, and OAuth, Azure or LDAP based authentication.

Finally, PyAMS_security provides ACLs and roles management, as well as custom schema fields to
store roles assigned to principals.
