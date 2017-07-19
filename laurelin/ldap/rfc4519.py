"""RFC 4519: Schema for User Applications

https://tools.ietf.org/html/rfc4519
"""

from __future__ import absolute_import
from .attributetype import AttributeType
from .objectclass import ObjectClass

## Attribute Types

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


## Object Classes


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
