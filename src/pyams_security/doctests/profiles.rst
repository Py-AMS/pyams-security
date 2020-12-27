
======================
Managing users profile
======================

PyAMS provides a few features to help manage users profiles:

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

    >>> from pyams_security.principal import PrincipalInfo
    >>> from pyams_site.generations import upgrade_site

    >>> request = new_test_request('admin', 'admin', registry=config.registry)
    >>> app = upgrade_site(request)
    Upgrading PyAMS timezone to generation 1...
    Upgrading PyAMS catalog to generation 1...
    Upgrading PyAMS file to generation 3...
    Upgrading PyAMS security to generation 2...

    >>> request.root = app
    >>> request.principal = PrincipalInfo(id='system:admin')

    >>> from zope.traversing.interfaces import BeforeTraverseEvent
    >>> from pyams_utils.registry import handle_site_before_traverse
    >>> handle_site_before_traverse(BeforeTraverseEvent(app, request))

By default, the PublicProfile class only provides a simple avatar:

    >>> from pyams_security.interfaces.profile import IPublicProfile
    >>> from pyams_security.profile import PublicProfile

    >>> profile = IPublicProfile(request)
    >>> profile
    <pyams_security.profile.PublicProfile object at 0x...>
    >>> pprint.pprint(profile.__acl__())
    [('Allow',
      'system:admin',
      <pyramid.security.AllPermissionsList object at 0x...>),
     ('Allow', 'system.Everyone', 'public')]

    >>> profile.__name__
    '++profile++...'
    >>> profile_name = profile.__name__.split('++')[2]

An IPublicProfile adapter is available for any object:

    >>> app_profile = IPublicProfile(app)
    >>> app_profile
    <pyams_security.profile.PublicProfile object at 0x...>
    >>> app_profile is profile
    True

A custom "++profile++" namespace traverser is also available; it allows, for example, to
get access to the avatar of a given principal:

    >>> from pyams_security.profile import ProfileTraverser
    >>> traverser = ProfileTraverser(app, request)

Without name, you get access to request's profile:

    >>> request_profile = traverser.traverse('')
    >>> request_profile is profile
    True

You can also specify a custom profile ID:

    >>> current_profile = traverser.traverse(profile_name)
    >>> current_profile is profile
    True

"public_profile" is a TALES extension which can also be used to get access to a user's profile
from a Chameleon template:

    >>> from pyams_utils.interfaces.tales import ITALESExtension
    >>> extension = config.registry.getMultiAdapter((app, request), ITALESExtension,
    ...                                             name='public_profile')
    >>> extension.render() is profile
    True


Tests cleanup:

    >>> tearDown()
