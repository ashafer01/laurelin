"""RFC 2696 Simple Paged Results Manipulation

This adds a control to support paging results. Use the control keyword ``paged`` with search methods. Returns a cookie
on the ``page_cookie`` response attribute which can be found on the results handle after all paged results have been
received. See example below.

Note: Do not use this extension to simply limit the total number of results. The search methods accept a ``limit``
keyword out of the box for this purpose.

Example usage::

    from laurelin.ldap import LDAP
    LDAP.activate_extension('laurelin.extensions.pagedresults')

    with LDAP() as ldap:
        search = ldap.base.search(paged=10)
        page1_results = list(search)

        search = ldap.base.search(paged=(10, search.page_cookie))
        page2_results = list(search)

        # ...

        if not search.page_cookie:
            print('Got all pages')

Note: When getting pages in a loop, you may set the cookie value to an empty string on the first iteration, e.g.::

    ldap.base.search(paged=(10, ''))
"""

from laurelin.ldap import Control, BaseLaurelinExtension, LDAPError
from laurelin.ldap.protoutils import get_string_component
from laurelin.ldap.rfc4511 import Integer0ToMax
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.type.univ import OctetString, Sequence
from pyasn1.type.namedtype import NamedTypes, NamedType

OID = '1.2.840.113556.1.4.319'


class Size(Integer0ToMax):
    pass


class Cookie(OctetString):
    pass


class RealSearchControlValue(Sequence):
    # realSearchControlValue ::= SEQUENCE {
    #         size            INTEGER (0..maxInt),
    #                                 -- requested page size from client
    #                                 -- result set size estimate from server
    #         cookie          OCTET STRING
    # }
    componentType = NamedTypes(NamedType('size', Size()),
                               NamedType('cookie', Cookie()))


class LaurelinExtension(BaseLaurelinExtension):
    NAME = 'paged_results'

    OID = OID

    class PagedResultsControl(Control):
        REQUEST_OID = OID
        RESPONSE_OID = OID
        method = ('search',)
        keyword = 'paged'
        response_attr = 'page_cookie'

        def prepare(self, ctrl_value, criticality):
            """Prepare the paged results control value

            :param ctrl_value: Either an integer page size or a tuple of (page size, cookie)
            :type ctrl_value: int or tuple
            :param criticality: True if the control is critical, false otherwise
            :return: The protocol-level control object
            """
            if isinstance(ctrl_value, int):
                page_size = ctrl_value
                cookie = ''
            elif isinstance(ctrl_value, tuple):
                page_size, cookie = ctrl_value
            else:
                raise TypeError('Must be int or tuple')
            real_ctrl_value = RealSearchControlValue()
            real_ctrl_value.setComponentByName('size', Size(page_size))
            real_ctrl_value.setComponentByName('cookie', Cookie(cookie))
            real_ctrl_value = ber_encode(real_ctrl_value)
            return Control.prepare(self, real_ctrl_value, criticality)

        def handle(self, ctrl_value):
            real_ctrl_value, raw = ber_decode(ctrl_value, asn1Spec=RealSearchControlValue())
            if raw:
                raise LDAPError('Unexpected leftover bits in response control value')
            cookie = get_string_component(real_ctrl_value, 'cookie')
            return cookie
