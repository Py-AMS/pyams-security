
============================
PyAMS REST services security
============================

PyAMS_security package provides a few helpers to improve security of REST services,
actually concerning CORS requests.

    >>> import pprint

    >>> from pyramid.testing import tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
    >>> from pyramid.threadlocal import manager
    >>> config = setup_tests_registry()
    >>> config.registry.settings['zodbconn.uri'] = 'memory://'

    >>> from pyramid_zodbconn import includeme as include_zodbconn
    >>> include_zodbconn(config)
    >>> from cornice import includeme as include_cornice
    >>> include_cornice(config)
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


CORS configuration
------------------

CORS configuration is handled by a specific interface:

    >>> from pyams_security.interfaces.rest import ICORSSecurityInfo
    >>> cors_config = ICORSSecurityInfo(sm)
    >>> cors_config
    <pyams_security.rest.CORSSecurityInfo object at 0x...>
    >>> cors_config.restrict_origins
    True
    >>> cors_config.allowed_origins is None
    True


REST services validators
------------------------

PyAMS_security provides validators which can be used to restrict access to REST
services.

    >>> from pyams_security.rest import check_cors_origin, set_cors_headers

Let's try to check a simple service:

    >>> request = DummyRequest('/api/rest/test', method='OPTIONS')
    >>> check_cors_origin(request)

Nothing notable here, let's create a CORS request:

    >>> request = DummyRequest('/api/rest/test', method='OPTIONS',
    ...                        headers={
    ...                            'Origin': 'http://another-site.com'
    ...                        })
    >>> check_cors_origin(request)
    Traceback (most recent call last):
    ...
    pyramid.httpexceptions.HTTPBadRequest: Forbidden origin

We can disable origin checking, or add selected origin to our configuration:

    >>> cors_config.restrict_origins = False
    >>> check_cors_origin(request)

    >>> cors_config.restrict_origins = True
    >>> cors_config.allowed_origins = ['http://another-site.com']
    >>> check_cors_origin(request)

A complete CORS request should include more headers:

    >>> request = DummyRequest('/api/rest/test', method='OPTIONS',
    ...                        headers={
    ...                            'Origin': 'http://another-site.com',
    ...                            'Access-Control-Request-Headers': 'origin',
    ...                            'Access-Control-Request-Method': 'GET'
    ...                        })
    >>> set_cors_headers(request)
    >>> sorted(request.response.headers.keys())
    ['Access-Control-Allow-Credentials', 'Access-Control-Allow-Headers',
     'Access-Control-Allow-Origin', 'Content-Length', 'Content-Type']
    >>> request.response.headers['Access-Control-Allow-Credentials']
    'true'
    >>> request.response.headers['Access-Control-Allow-Origin']
    'http://another-site.com'

This feature is also available as a CORS request handler:

    >>> from zope.interface import alsoProvides
    >>> from pyams_utils.request import PyAMSRequest
    >>> from pyams_utils.interfaces.rest import ICORSRequestHandler
    >>> from pyams_utils.rest import handle_cors_headers
    >>> from pyams_layer.interfaces import IPyAMSLayer

    >>> request = PyAMSRequest({})
    >>> request.scheme = 'http'
    >>> request.host = 'example.com'
    >>> request.registry = config.registry
    >>> request.headers['Origin'] = 'http://another-site.com'
    >>> alsoProvides(request, IPyAMSLayer)
    >>> handle_cors_headers(request)

    >>> request.response.headers['Access-Control-Allow-Credentials']
    'true'
    >>> request.response.headers['Access-Control-Allow-Origin']
    'http://another-site.com'

To set allowed methods on services which are not based on Cornice, you can add another
argument:

    >>> request.headers['Access-Control-Request-Method'] = 'GET'
    >>> handle_cors_headers(request, allowed_methods=('GET', 'OPTIONS'))
    >>> sorted(request.response.headers)
    ['Access-Control-Allow-Credentials', 'Access-Control-Allow-Methods',
     'Access-Control-Allow-Origin', 'Content-Length', 'Content-Type']
    >>> request.response.headers['Access-Control-Allow-Methods']
    'GET, OPTIONS'


Tests cleanup:

    >>> tearDown()
