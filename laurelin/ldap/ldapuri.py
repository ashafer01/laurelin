"""Functions and classes relating to LDAP URIs and search references"""

from __future__ import absolute_import
from warnings import warn
from .base import LDAP, Scope
from .errors import LDAPError, LDAPConnectionError
from six.moves.urllib.parse import urlparse

def searchByURI(uri):
    """Perform a search based on an RFC4516 URI and return an iterator over search results

     Opens a new connection with connection reuse disabled, performs the search, and unbinds the
     connection. Server must allow anonymous read.
    """
    parsedURI = LDAPURI(uri)
    ldap = LDAP(parsedURI.hostURI, reuseConnection=False)
    for obj in ldap.search(parsedURI.DN, parsedURI.scope, filterStr=parsedURI.filter,
        attrs=parsedURI.attrs):
        yield obj
    ldap.unbind()

def searchByURIAll(uri):
    """Same as searchByURI but returns all results in a list"""
    parsedURI = LDAPURI(uri)
    ldap = LDAP(parsedURI.hostURI, reuseConnection=False)
    ret = ldap.searchAll(parsedURI.DN, parsedURI.scope, filterStr=parsedURI.filter,
        attrs=parsedURI.attrs)
    ldap.unbind()
    return ret

class LDAPURI(object):
    """Represents a parsed LDAP URI as specified in RFC4516

     Attributes:
     * scheme   - urlparse standard
     * netloc   - urlparse standard
     * hostURI  - scheme://netloc for use with LDAPSocket
     * DN       - string
     * attrs    - list
     * scope    - one of the Scope.* constants
     * filter   - string
     * Extensions not yet implemented
    """
    def __init__(self, uri):
        parsedURI = urlparse(uri)
        self.scheme = parsedURI.scheme
        self.netloc = parsedURI.netloc
        self.hostURI = '{0}://{1}'.format(self.scheme, self.netloc)
        self.DN = parsedURI.path
        params = parsedURI.query.split('?')
        nparams = len(params)
        if (nparams > 0) and (len(params[0]) > 0):
            self.attrs = params[0].split(',')
        else:
            self.attrs = [LDAP.ALL_USER_ATTRS]
        if (nparams > 1) and (len(params[1]) > 0):
            self.scope = Scope.string(params[1])
        else:
            self.scope = Scope.BASE
        if (nparams > 2) and (len(params[2]) > 0):
            self.filter = params[2]
        else:
            self.filter = LDAP.DEFAULT_FILTER
        if (nparams > 3) and (len(params[3]) > 0):
            raise LDAPError('Extensions for searchByURI not yet implemented')

class SearchReferenceHandle(object):
    """Returned when the server returns a SearchResultReference"""
    def __init__(self, URIs):
        self.URIs = URIs
        self._resultIter = None
        self._resultList = None

    def fetch(self):
        """Perform the reference search and return an iterator over results

         Each handle will only create one iterator for its results
        """
        if self._resultIter is None:
            # If multiple URIs are present, the client assumes that any supported URI
            # may be used to progress the operation. ~ RFC4511 sec 4.5.3 p28
            for uri in self.URIs:
                try:
                    self._resultIter = searchByURI(uri)
                    break
                except LDAPConnectionError as e:
                    warn('Error connecting to URI {0} ({1})'.format(uri, e.message))
            raise LDAPError('Could not complete reference URI search with any supplied URIs')
        return self._resultIter

    def fetchAll(self):
        """Fetch all reference search results into a list

         If fetch() was called prior to this, then all remaining results on the iterator will be
         fetched into a list and returned.
        """
        if self._resultIter is not None and self._resultList is None:
            self._resultList = []
            for o in self._resultIter:
                self._resultList.append(o)
        if self._resultList is None:
            for uri in self.URIs:
                try:
                    self._resultList = searchByURIAll(uri)
                    break
                except LDAPConnectionError as e:
                    warn('Error connecting to URI {0} ({1})'.format(uri, e.message))
            raise LDAPError('Could not complete reference URI search with any supplied URIs')
        return self._resultList
