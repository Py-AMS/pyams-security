
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

You can also define a subscriber predicate using a class or an interface:

    >>> from pyams_security.plugin.admin import AdminAuthenticationPlugin
    >>> plugin = AdminAuthenticationPlugin()

    >>> from pyams_security.interfaces import IAdminAuthenticationPlugin
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
