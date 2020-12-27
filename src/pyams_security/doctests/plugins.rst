
======================
PyAMS security plugins
======================

PyAMS security plugins can be utilities registered into the global registry, or local
utilities registered into the local components registry.

    >>> from pyramid.testing import setUp, tearDown
    >>> config = setUp()


Plugins events
--------------

Several events are notified when using security plugins; for example, when a principal is
authenticated, an *AuthenticatedPrincipalEvent* event is notified.

You can add a predicate on plugins events to filter events based on their original plugin:

    >>> from pyams_security.plugin import PluginSelector

    >>> selector = PluginSelector('admin', config)
    >>> selector.text()
    'plugin_selector = admin'

    >>> from pyams_security.interfaces import AuthenticatedPrincipalEvent
    >>> event = AuthenticatedPrincipalEvent('admin', 'admin')
    >>> selector(event)
    True

You can also define a subscriber predicate using a class or an interface; we just have to
call the "factory_config" decorator for testing:

    >>> from pyams_utils.testing import call_decorator
    >>> from pyams_utils.factory import factory_config
    >>> from pyams_security.interfaces import IAdminAuthenticationPlugin
    >>> from pyams_security.plugin.admin import AdminAuthenticationPlugin

    >>> call_decorator(config, factory_config, AdminAuthenticationPlugin,
    ...                IAdminAuthenticationPlugin)

    >>> plugin = AdminAuthenticationPlugin()

    >>> selector = PluginSelector(IAdminAuthenticationPlugin, config)
    >>> event = AuthenticatedPrincipalEvent(plugin, 'admin')
    >>> selector(event)
    True

    >>> selector = PluginSelector(AdminAuthenticationPlugin, config)
    >>> selector(event)
    True

    >>> selector = PluginSelector(PluginSelector, config)
    >>> selector(event)
    False


Tests cleanup:

    >>> tearDown()
