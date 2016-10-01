class LDAPError(Exception):
    """Base class for all exceptions raised by laurelin"""
    pass

class LDAPExtensionError(LDAPError):
    """Error occurred setting up an extension module"""
    pass

class LDAPSASLError(LDAPError):
    """Error occurred involving the SASL client"""
    pass

class LDAPConnectionError(LDAPError):
    """Error occurred creating connection to the LDAP server"""
    pass

class TagError(LDAPError):
    """Error with an object tag"""
    pass

class UnexpectedResponseType(LDAPError):
    """The response did not contain the expected protocol operation"""
    pass

class UnexpectedSearchResults(LDAPError):
    """Base class for unhandled search result situations"""
    pass

class NoSearchResults(UnexpectedSearchResults):
    """Got no search results when one ore more was required"""
    pass

class MultipleSearchResults(UnexpectedSearchResults):
    """Got multiple search results when exactly one was required"""
    pass

class InvalidBindState(LDAPError):
    """Base class for exceptions related to bind state"""
    pass

class ConnectionAlreadyBound(InvalidBindState):
    """Only raised by LDAP.*Bind methods if the connection is already bound when called"""
    def __init__(self):
        LDAPError.__init__(self, 'The connection has already been bound')

class ConnectionUnbound(InvalidBindState):
    """Raised when any server operation is attempted after a connection is unbound/closed"""
    def __init__(self):
        LDAPError.__init__(self, 'The connection has been unbound')
