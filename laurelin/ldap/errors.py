class LDAPError(Exception):
    pass

class LDAPExtensionError(LDAPError):
    pass

class LDAPSASLError(LDAPError):
    pass

class TagError(LDAPError):
    pass

class UnexpectedResponseType(LDAPError):
    pass

class UnexpectedSearchResults(LDAPError):
    pass

class NoSearchResults(UnexpectedSearchResults):
    pass

class MultipleSearchResults(UnexpectedSearchResults):
    pass

class InvalidBindState(LDAPError):
    pass

class ConnectionAlreadyBound(InvalidBindState):
    def __init__(self):
        LDAPError.__init__(self, 'The connection has already been bound')

class ConnectionUnbound(InvalidBindState):
    def __init__(self):
        LDAPError.__init__(self, 'The connection has been unbound')

class AbandonedAsyncError(LDAPError):
    pass
