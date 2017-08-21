from .attributetype import getAttributeType
from .exceptions import LDAPValidationError, LDAPWarning
from .objectclass import getObjectClass

import six
from six.moves import range

_validators = []

def getValidators():
    return _validators


class MetaValidator(type):
    """Metaclass which registers instances of subclasses"""
    def __new__(meta, name, bases, dct):
        cls = type.__new__(meta, name, bases, dct)
        if not name.startswith('Base'):
            _validators.append(cls())
        return cls


@six.add_metaclass(MetaValidator)
class BaseValidator(object):
    pass


class SchemaValidator(BaseValidator):
    """Ensures parameters conform to the available defined schema"""

    def validateObject(self, obj, write=True):
        """Validates an object when all attributes are present

         * Requires the objectClass attribute
         * Checks that all attributes required by the objectClass are defined
         * Checks that all attributes are allowed by the objectClass
         * Performs validation against the attribute type spec for all attributes
        """
        try:
            objectClasses = obj['objectClass']
        except KeyError:
            raise LDAPValidationError('missing objectClass')
        attrs = list(obj.keys())
        for ocName in objectClasses:
            oc = getObjectClass(ocName)
            for reqdAttr in oc.must:
                if reqdAttr not in attrs:
                    raise LDAPValidationError('missing attribute {0} required by objectClass {1}'.format(reqdAttr, ocName))
                else:
                    attrs.remove(reqdAttr)
            for attr in attrs:
                if attr in oc.may:
                    attrs.remove(attr)
        if attrs:
            disallowedAttrs = ','.join(attrs)
            ocNames = ','.join(objectClasses)
            raise LDAPValidationError('attributes {0} are not permitted with objectClasses {1}'.format(disallowedAttrs, ocNames))
        self.validateAttributes(obj, write)

    def validateModify(self, modlist, current):
        for mod in modlist:
            if mod.vals:
                self._validateAttribute(mod.attr, mod.vals, True)

    def _validateAttribute(self, attrName, values, write):
        attr = getAttributeType(attrName)
        if attr.obsolete:
            warn('Attribute {0} is obsolete'.format(attrName), LDAPWarning)
        if attr.singleValue and len(values) > 1:
            raise LDAPValidationError('Multiple values for single-value attribute {0}'.format(attrName))
        if write and attr.noUserMod:
            raise LDAPValidationError('Attribute {0} is not user modifiable'.format(attrName))
        for value in values:
            attr.validate(value)
