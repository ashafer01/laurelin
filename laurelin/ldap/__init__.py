__all__ = []

from base import LDAP, LDAP_rw, LDAPObject, Scope, DerefAliases
from modify import Mod, Modlist, AddModlist, DeleteModlist, ReplaceModlist
from errors import LDAPError

# perform a search based on an RFC4516 URI
def searchByURI(uri):
    parsedURI = urlparse(uri)
    hostURI = '{0}://{1}'.format(parsedURI.scheme, parsedURL.netloc)
    ldap = LDAP(hostURI, reuseConnection=False)
    DN = parsedURI.path
    params = parsedURI.query.split('?')
    nparams = len(params)
    if (nparams > 0) and (len(params[0]) > 0):
        attrList = params[0].split(',')
    else:
        attrList = [LDAP.ALL_USER_ATTRS]
    if (nparams > 1) and (len(params[1]) > 0):
        scope = Scope.string(params[1])
    else:
        scope = Scope.BASE
    if (nparams > 2) and (len(params[2]) > 0):
        filter = params[2]
    else:
        filter = LDAP.DEFAULT_FILTER
    if (nparams > 3) and (len(params[3]) > 0):
        raise LDAPError('Extensions for searchByURI not yet implemented')
    ret = ldap.search(DN, scope, filterStr=filter, attrList=attrList)
    ldap.unbind()
    return ret
