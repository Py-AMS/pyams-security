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

PyAMS_security is a core extension package for PyAMS which provides all main security-related
features; the package provides a custom authentication policy which is based on a custom "security
manager". This utility is a pluggable tool which is handling system users, local users and groups,
as well as OAuth authentication; external packages can also provide authentication based
on an LDAP directory.

PyAMS_security also provides utilities to extract credentials from queries, like HTTP basic
authentication or JWT tokens, and can also provide your own credentials extraction mechanisms.

Finally, PyAMS_security provides roles management, as well as custom schema fields to store
roles assigned to principals.
