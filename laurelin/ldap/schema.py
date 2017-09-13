"""Schema specifications from various RFCs"""

from __future__ import absolute_import
from .attributetype import getAttributeType, AttributeType
from .exceptions import LDAPValidationError, LDAPWarning
from .objectclass import getObjectClass, ObjectClass, ExtensibleObjectClass
from .validation import BaseValidator

# load standard syntaxes and matching rules
from . import rfc4517


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
        for attr, values in six.iteritems(obj):
            self._validateAttribute(attr, values, write)

    def validateModify(self, dn, modlist, current):
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


## RFC 4512 2.4.1 Abstract Object Classes


ObjectClass("""( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )""")


## RFC 4512 2.6 Alias Entries


ObjectClass("""
      ( 2.5.6.1 NAME 'alias'
        SUP top STRUCTURAL
        MUST aliasedObjectName )
""")

AttributeType("""
      ( 2.5.4.1 NAME 'aliasedObjectName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE )
""")


## RFC 4512 Section 3 - Administrative/Operational


AttributeType("""
      ( 2.5.4.0 NAME 'objectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )
""")


AttributeType("""
      ( 2.5.18.3 NAME 'creatorsName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.1 NAME 'createTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.4 NAME 'modifiersName'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.18.2 NAME 'modifyTimestamp'
        EQUALITY generalizedTimeMatch
        ORDERING generalizedTimeOrderingMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.24
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.9 NAME 'structuralObjectClass'
        EQUALITY objectIdentifierMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.38
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.10 NAME 'governingStructureRule'
        EQUALITY integerMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.27
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")


## RFC 4512 4.2 Subschema Subentries


AttributeType("""
      ( 2.5.18.10 NAME 'subschemaSubentry'
        EQUALITY distinguishedNameMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.12
        SINGLE-VALUE NO-USER-MODIFICATION
        USAGE directoryOperation )
""")

ObjectClass("""
      ( 2.5.20.1 NAME 'subschema' AUXILIARY
        MAY ( dITStructureRules $ nameForms $ ditContentRules $
          objectClasses $ attributeTypes $ matchingRules $
          matchingRuleUse ) )

""")

AttributeType("""
      ( 2.5.21.6 NAME 'objectClasses'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.37
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.5 NAME 'attributeTypes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.3
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.4 NAME 'matchingRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.30
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.8 NAME 'matchingRuleUse'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.31
        USAGE directoryOperation )
""")

AttributeType("""
      ( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.54
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.2 NAME 'dITContentRules'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.16
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.1 NAME 'dITStructureRules'
        EQUALITY integerFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.17
        USAGE directoryOperation )
""")

AttributeType("""
      ( 2.5.21.7 NAME 'nameForms'
        EQUALITY objectIdentifierFirstComponentMatch
        SYNTAX 1.3.6.1.4.1.1466.115.121.1.35
        USAGE directoryOperation )
""")


## RFC 4512 4.3 extensibleObject


ExtensibleObjectClass("""
      ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject'
              SUP top AUXILIARY )
""")


## RFC 4519 Attribute Types


AttributeType("""
      ( 2.5.4.15 NAME 'businessCategory'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.6 NAME 'c'
         SUP name
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.11
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.3 NAME 'cn'
         SUP name )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.25 NAME 'dc'
         EQUALITY caseIgnoreIA5Match
         SUBSTR caseIgnoreIA5SubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.26
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.13 NAME 'description'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.27 NAME 'destinationIndicator'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.49 NAME 'distinguishedName'
         EQUALITY distinguishedNameMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )
""")

AttributeType("""
      ( 2.5.4.46 NAME 'dnQualifier'
         EQUALITY caseIgnoreMatch
         ORDERING caseIgnoreOrderingMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.47 NAME 'enhancedSearchGuide'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.21 )
""")

AttributeType("""
      ( 2.5.4.23 NAME 'facsimileTelephoneNumber'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.22 )
""")

AttributeType("""
      ( 2.5.4.44 NAME 'generationQualifier'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.42 NAME 'givenName'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.51 NAME 'houseIdentifier'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.43 NAME 'initials'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.25 NAME 'internationalISDNNumber'
         EQUALITY numericStringMatch
         SUBSTR numericStringSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
""")

AttributeType("""
      ( 2.5.4.7 NAME 'l'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.31 NAME 'member'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.41 NAME 'name'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.10 NAME 'o'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.11 NAME 'ou'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.32 NAME 'owner'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.19 NAME 'physicalDeliveryOfficeName'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.16 NAME 'postalAddress'
         EQUALITY caseIgnoreListMatch
         SUBSTR caseIgnoreListSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
""")

AttributeType("""
      ( 2.5.4.17 NAME 'postalCode'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.18 NAME 'postOfficeBox'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.28 NAME 'preferredDeliveryMethod'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.14
         SINGLE-VALUE )
""")

AttributeType("""
      ( 2.5.4.26 NAME 'registeredAddress'
         SUP postalAddress
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.41 )
""")

AttributeType("""
      ( 2.5.4.33 NAME 'roleOccupant'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.34 NAME 'seeAlso'
         SUP distinguishedName )
""")

AttributeType("""
      ( 2.5.4.5 NAME 'serialNumber'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )
""")

AttributeType("""
      ( 2.5.4.4 NAME 'sn'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.8 NAME 'st'
         SUP name )
""")

AttributeType("""
      ( 2.5.4.9 NAME 'street'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.20 NAME 'telephoneNumber'
         EQUALITY telephoneNumberMatch
         SUBSTR telephoneNumberSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.50 )
""")

AttributeType("""
      ( 2.5.4.21 NAME 'telexNumber'
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.52 )
""")

AttributeType("""
      ( 2.5.4.12 NAME 'title'
         SUP name )
""")

AttributeType("""
      ( 0.9.2342.19200300.100.1.1 NAME 'uid'
         EQUALITY caseIgnoreMatch
         SUBSTR caseIgnoreSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
""")

AttributeType("""
      ( 2.5.4.50 NAME 'uniqueMember'
         EQUALITY uniqueMemberMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.34 )
""")

AttributeType("""
      ( 2.5.4.35 NAME 'userPassword'
         EQUALITY octetStringMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )
""")

AttributeType("""
      ( 2.5.4.24 NAME 'x121Address'
         EQUALITY numericStringMatch
         SUBSTR numericStringSubstringsMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.36 )
""")

AttributeType("""
      ( 2.5.4.45 NAME 'x500UniqueIdentifier'
         EQUALITY bitStringMatch
         SYNTAX 1.3.6.1.4.1.1466.115.121.1.6 )
""")


## RFC 4519 Object Classes


ObjectClass("""
      ( 2.5.6.11 NAME 'applicationProcess'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( seeAlso $
               ou $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.2 NAME 'country'
         SUP top
         STRUCTURAL
         MUST c
         MAY ( searchGuide $
               description ) )
""")

ObjectClass("""
      ( 1.3.6.1.4.1.1466.344 NAME 'dcObject'
         SUP top
         AUXILIARY
         MUST dc )
""")

ObjectClass("""
      ( 2.5.6.14 NAME 'device'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( serialNumber $
               seeAlso $
               owner $
               ou $
               o $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.9 NAME 'groupOfNames'
         SUP top
         STRUCTURAL
         MUST ( member $
               cn )
         MAY ( businessCategory $
               seeAlso $
               owner $
               ou $
               o $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.17 NAME 'groupOfUniqueNames'
         SUP top
         STRUCTURAL
         MUST ( uniqueMember $
               cn )
         MAY ( businessCategory $
               seeAlso $
               owner $
               ou $
               o $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.3 NAME 'locality'
         SUP top
         STRUCTURAL
         MAY ( street $
               seeAlso $
               searchGuide $
               st $
               l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.4 NAME 'organization'
         SUP top
         STRUCTURAL
         MUST o
         MAY ( userPassword $ searchGuide $ seeAlso $
               businessCategory $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ street $ postOfficeBox $
               postalCode $ postalAddress $ physicalDeliveryOfficeName $
               st $ l $ description ) )
""")

ObjectClass("""
      ( 2.5.6.7 NAME 'organizationalPerson'
         SUP person
         STRUCTURAL
         MAY ( title $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ street $ postOfficeBox $
               postalCode $ postalAddress $ physicalDeliveryOfficeName $
               ou $ st $ l ) )
""")

ObjectClass("""
      ( 2.5.6.8 NAME 'organizationalRole'
         SUP top
         STRUCTURAL
         MUST cn
         MAY ( x121Address $ registeredAddress $ destinationIndicator $
               preferredDeliveryMethod $ telexNumber $
               teletexTerminalIdentifier $ telephoneNumber $
               internationalISDNNumber $ facsimileTelephoneNumber $
               seeAlso $ roleOccupant $ preferredDeliveryMethod $
               street $ postOfficeBox $ postalCode $ postalAddress $
               physicalDeliveryOfficeName $ ou $ st $ l $
               description ) )
""")

ObjectClass("""
      ( 2.5.6.5 NAME 'organizationalUnit'
         SUP top
         STRUCTURAL
         MUST ou
         MAY ( businessCategory $ description $ destinationIndicator $
               facsimileTelephoneNumber $ internationalISDNNumber $ l $
               physicalDeliveryOfficeName $ postalAddress $ postalCode $
               postOfficeBox $ preferredDeliveryMethod $
               registeredAddress $ searchGuide $ seeAlso $ st $ street $
               telephoneNumber $ teletexTerminalIdentifier $
               telexNumber $ userPassword $ x121Address ) )
""")

ObjectClass("""
      ( 2.5.6.6 NAME 'person'
         SUP top
         STRUCTURAL
         MUST ( sn $
               cn )
         MAY ( userPassword $
               telephoneNumber $
               seeAlso $ description ) )
""")

ObjectClass("""
      ( 2.5.6.10 NAME 'residentialPerson'
         SUP person
         STRUCTURAL
         MUST l
         MAY ( businessCategory $ x121Address $ registeredAddress $
               destinationIndicator $ preferredDeliveryMethod $
               telexNumber $ teletexTerminalIdentifier $
               telephoneNumber $ internationalISDNNumber $
               facsimileTelephoneNumber $ preferredDeliveryMethod $
               street $ postOfficeBox $ postalCode $ postalAddress $
               physicalDeliveryOfficeName $ st $ l ) )
""")

ObjectClass("""
      ( 1.3.6.1.1.3.1 NAME 'uidObject'
         SUP top
         AUXILIARY
         MUST uid )
""")

