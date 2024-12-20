#
# Copyright (c) 2008-2015 Thierry Florac <tflorac AT ulthar.net>
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#

"""PyAMS_security.principal module

This module provides principal related classes.
"""

from zope.annotation.interfaces import IAnnotations
from zope.interface import implementer
from zope.location.interfaces import ISublocations
from zope.principalannotation.interfaces import IPrincipalAnnotationUtility
from zope.schema.fieldproperty import FieldProperty

from pyams_security.interfaces.base import IMissingPrincipalInfo, IPrincipalInfo, IUnavailablePrincipalInfo, \
    IUnknownPrincipalInfo
from pyams_security.interfaces.names import UNKNOWN_PRINCIPAL_ID
from pyams_site.interfaces import ISiteRoot
from pyams_utils.adapter import ContextAdapter, adapter_config
from pyams_utils.registry import query_utility


__docformat__ = 'restructuredtext'

from pyams_security import _  # pylint: disable=ungrouped-imports


@implementer(IPrincipalInfo)
class PrincipalInfo:
    """Generic principal info"""

    id = FieldProperty(IPrincipalInfo['id'])  # pylint: disable=invalid-name
    title = FieldProperty(IPrincipalInfo['title'])
    attributes = FieldProperty(IPrincipalInfo['attributes'])

    def __init__(self, **kwargs):
        self.id = kwargs.pop('id')  # pylint: disable=invalid-name
        self.title = kwargs.pop('title', '__unknown__')
        self.attributes = kwargs

    def __eq__(self, other):
        return isinstance(other, PrincipalInfo) and (self.id == other.id)

    def __hash__(self):
        return hash(self.id)


@implementer(IUnknownPrincipalInfo)
class _UnknownPrincipal:
    """Unknown principal info"""

    id = UNKNOWN_PRINCIPAL_ID  # pylint: disable=invalid-name
    title = _("< unknown principal >")


UnknownPrincipal = _UnknownPrincipal()  # pylint: disable=invalid-name


@implementer(IMissingPrincipalInfo)
class MissingPrincipal:
    """Missing principal info

    This class can be used when a stored principal ID
    references a principal which can't be found anymore
    """

    id = FieldProperty(IPrincipalInfo['id'])  # pylint: disable=invalid-name

    def __init__(self, **kwargs):
        self.id = kwargs.get('id')  # pylint: disable=invalid-name

    @property
    def title(self):
        """Get principal title"""
        return 'MissingPrincipal: {id}'.format(id=self.id)

    def __eq__(self, other):
        return isinstance(other, PrincipalInfo) and (self.id == other.id)


@adapter_config(required=IPrincipalInfo, provides=IAnnotations)
def get_principal_annotations(principal):
    """Principal annotations adapter"""
    annotations = query_utility(IPrincipalAnnotationUtility)
    if annotations is not None:
        return annotations.getAnnotations(principal)
    return None


@adapter_config(required=IUnavailablePrincipalInfo, provides=IAnnotations)
def unavailable_principal_annotations(principal):
    """Unavailable principal annotations adapter"""
    return None


@adapter_config(name='principal.annotations',
                required=ISiteRoot,
                provides=ISublocations)
class PrincipalAnnotationsSublocation(ContextAdapter):
    """Principal annotations utility sub-location adapter"""

    def sublocations(self):  # pylint: disable=no-self-use
        """Principal annotations utility sublocations"""
        utility = query_utility(IPrincipalAnnotationUtility)
        if utility is not None:
            for annotation in utility.annotations.values():
                yield from annotation.data.values()
