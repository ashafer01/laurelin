##
## ldap.tree
##
## Used to declare an LDAP tree structure to simplify searching

from base import Scope

class LDAPTreeNode(object):
    def __init__(self, dn, root, tag=None, dnAttr=None, searchScope=None, delegate=None):
        self.dn = dn
        self.root = root
        self.nodes = []
        self.tag = tag
        if searchScope is None:
            searchScope = Scope.ONELEVEL
        self.searchScope = searchScope
        self.dnAttr = dnAttr
        if delegate is None:
            self.delegate = self.root.delegate

    def addNode(self, dnPrefix, tag=None, dnAttr=None, searchScope=None):
        dn = self.childDN(dnPrefix)
        node = LDAPTreeNode(dn, self.root, tag, searchScope)
        if tag is not None:
            self.root.tags[tag] = node
        self.nodes.append(node)

    def childDN(self, dnPrefix):
        if '=' not in dnPrefix:
            if self.dnAttr is not None:
                dnPrefix = '{0}={1}'.format(self.dnAttr, dnPrefix)
            else:
                raise ValueError()
        return '{0},{1}'.format(dnPrefix, self.dn)

    def search(self, dnPrefix, *args, **kwds):
        if self.root.delegate is not None:
            return self.root.delegate.search(self.childDN(dnPrefix), self.searchScope, *args, **kwds)
        else:
            raise RuntimeError('No connection delegate')

class LDAPTree(LDAPTreeNode):
    def __init__(self, dc, delegate=None):
        # validate dc
        for dcpart in dc.split(','):
            if not dcpart.startswith('dc='):
                raise ValueError('Invalid base domain component')
        self.dn = dc
        self.root = self
        self.nodes = []
        self.searchScope = Scope.SUBTREE
        self.tags = {}
        self.delegate = delegate

    def tag(self, tag):
        return self.tags[tag]
