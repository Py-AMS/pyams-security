
============================
PyAMS_security notifications
============================

PyAMS_security package relies on the "notification" module to handle mail notifications:

    >>> from pyramid.testing import setUp, tearDown, DummyRequest
    >>> from pyams_security.tests import setup_tests_registry, new_test_request
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

    >>> from pyams_security.interfaces.notification import INotificationSettings
    >>> from pyams_security.notification import NotificationSettings

    >>> settings = NotificationSettings()
    >>> settings.enable_notifications = True
    >>> INotificationSettings.validateInvariants(settings)
    Traceback (most recent call last):
    ...
    zope.interface.exceptions.Invalid: Notifications can't be enabled without mailer utility

    >>> settings.get_mailer() is None
    True

    >>> settings.mailer = 'mailer'
    >>> INotificationSettings.validateInvariants(settings)

    >>> settings.get_mailer()
    <pyramid_mailer.mailer.DummyMailer object at 0x...>


Tests cleanup:

    >>> tearDown()
