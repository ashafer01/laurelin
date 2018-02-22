import unittest
from laurelin.ldap import LDAP, critical
from laurelin.extensions import pagedresults
from .mock_ldapsocket import MockLDAPSocket
from laurelin.ldap import rfc4511
from pyasn1.codec.ber.encoder import encode as ber_encode


class TestControls(unittest.TestCase):
    def test_pagedresults(self):
        """Use the paged results controls to exercise the controls subsystem"""
        LDAP.activate_extension('laurelin.extensions.pagedresults')
        mock_sock = MockLDAPSocket()
        mock_sock.add_search_res_entry('', {
            'supportedControl': [pagedresults.OID],
            'namingContexts': ['o=testing']
        })
        mock_sock.add_search_res_done('')
        ldap = LDAP(mock_sock)

        test_dn = 'o=testing'
        test_cookie = 'foo'
        test_size = 2

        # prepare response control
        controls = rfc4511.Controls()
        control = rfc4511.Control()
        ctrl_value = pagedresults.RealSearchControlValue()
        ctrl_value.setComponentByName('size', pagedresults.Size(test_size))
        ctrl_value.setComponentByName('cookie', pagedresults.Cookie(test_cookie))
        control.setComponentByName('controlType', rfc4511.LDAPOID(pagedresults.OID))
        control.setComponentByName('controlValue', ber_encode(ctrl_value))
        controls.setComponentByPosition(0, control)

        # prepare search results
        mock_sock.add_search_res_entry(test_dn, {})
        mock_sock.add_search_res_entry(test_dn, {})
        mock_sock.add_search_res_done(test_dn, controls=controls)

        # do search with critical
        ctrl_kwds = {pagedresults.PagedResultsControl.keyword: critical(test_size)}
        search = ldap.search(test_dn, **ctrl_kwds)

        # get all results
        results = list(search)

        self.assertEqual(len(results), test_size)
        self.assertTrue(hasattr(search, pagedresults.PagedResultsControl.response_attr))
        self.assertEqual(getattr(search, pagedresults.PagedResultsControl.response_attr), test_cookie)
