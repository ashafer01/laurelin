class LDAPError(Exception):
    """Base class for all exceptions raised by laurelin"""
    pass


class Abandon(Exception):
    """Can be raised to cleanly exit a context manager and abandon unread results"""
    pass


class LDAPWarning(Warning):
    """Generic LDAP warning category"""
    pass


class LDAPUnicodeWarning(LDAPWarning, UnicodeWarning):
    """Warning category for unicode issues relating to LDAP"""
    pass


class LDAPExtensionError(LDAPError):
    """Error occurred setting up an extension module"""
    pass


class LDAPSupportError(LDAPError):
    """A feature is not supported by the server"""
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
    """Got no search results when one or more was required"""
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


class ProhibitedCharacterError(LDAPError):
    """Raised when a prohibited character is detected in RFC4518 string prep"""
    pass


class LDAPSchemaError(LDAPError):
    """Error relating to setting up the LDAP schema"""
    pass


class LDAPValidationError(LDAPError):
    """Raised when validation fails"""
    pass


class InvalidSyntaxError(LDAPValidationError):
    """Raised when syntax validation fails"""
    pass


class LDAPTransactionError(LDAPError):
    """Raised by actions not included in a modify transaction"""
    pass
