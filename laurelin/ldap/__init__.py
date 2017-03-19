""" laurelin.ldap

Imports base objects for user import and defines user utility functions
"""

from .base import LDAP, LDAPObject, LDAPURI, Scope, DerefAliases, critical, optional
from .errors import LDAPError, NoSearchResults, Abandon

def dc(domain):
    """Convert a DNS dotted domain name to a DN with domain components"""
    return ','.join(['dc={0}'.format(dc) for dc in domain.split('.')])

def domain(dc):
    """Convert a DN with domain components to a DNS dotted domain name"""
    return '.'.join([i.split('=')[1] for i in dc.split(',')])
