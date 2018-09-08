from .registration import LaurelinRegistrar, LaurelinTransiter


class BaseLaurelinExtension(LaurelinRegistrar, LaurelinTransiter):
    """Base class for basic extension class. Can house schema and controls definitions."""
    NAME = '__undefined__'
    INSTANCE = None


class BaseLaurelinLDAPExtension(object):
    """Base class for extensions to the LDAP class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAP parent: The parent LDAP instance
        """
        self.parent = parent


class BaseLaurelinLDAPObjectExtension(object):
    """Base class for extensions to the LDAPObject class"""
    def __init__(self, parent):
        """
        :param laurelin.ldap.LDAPObject parent: The parent LDAPObject instance
        """
        self.parent = parent


class BaseLaurelinSchema(LaurelinTransiter):
    """Optional base class for a class defining schema elements - only subclassing LaurelinTransiter is required"""
    pass


class BaseLaurelinControls(LaurelinTransiter):
    """Optional base class for a class defining controls - only subclassing LaurelinTransiter is required"""
    pass
