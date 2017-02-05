""" laurelin.ldap

Imports base objects for user import and defines user utility functions
"""

from .base import LDAP, LDAPObject, Scope, DerefAliases, LDAPURI
from .errors import LDAPError, NoSearchResults

def dc(domain):
    return ','.join(['dc={0}'.format(dc) for dc in domain.split('.')])

def domain(dc):
    return '.'.join([i.split('=')[1] for i in dc.split(',')])

def searchByURI(uri):
    """Perform a search based on an RFC4516 URI and return an iterator over search results

     Opens a new connection with connection reuse disabled, performs the search, and unbinds the
     connection. Server must allow anonymous read.
    """
    parsedURI = LDAPURI(uri)
    ldap = LDAP(parsedURI.hostURI, reuseConnection=False)
    for obj in parsedURI.search(ldap):
        yield obj
    ldap.unbind()

def searchByURIAll(uri):
    """Same as searchByURI but returns all results in a list"""
    parsedURI = LDAPURI(uri)
    ldap = LDAP(parsedURI.hostURI, reuseConnection=False)
    ret = parsedURI.searchAll(ldap)
    ldap.unbind()
    return ret
