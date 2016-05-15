##
## pyasn1 implementation of RFC 4511 ASN.1 spec
## LDAP!
##

# NOTE: Some additional classes have been defined to implement common patterns
# found in the spec. These are flagged with a comment. Any classes defined
# within another class are implementations of inline definitions from the spec.

from pyasn1.type import univ, namedtype, namedval, tag, constraint

class NonEmptySetOf(univ.SetOf): # not in spec
    subtypeSpec = constraint.ValueSizeConstraint(1, float('inf'))

class NonEmptySequenceOf(univ.SequenceOf): # not in spec
    subtypeSpec = constraint.ValueSizeConstraint(1, float('inf'))

class LDAPString(univ.OctetString):
    pass
    # UTF-8 encoded, [ISO10646] characters

class LDAPOID(univ.OctetString):
    # Although an LDAPOID is
    # encoded as an OCTET STRING, values are limited to the definition of
    # <numericoid> given in Section 1.4 of [RFC4512]. For example,
    #     1.3.6.1.4.1.1466.1.2.3
    pass

maxInt = univ.Integer(2147483647) # (2^^31 - 1)
class NonNegativeInteger(univ.Integer): # not in spec
    subtypeSpec = constraint.ValueRangeConstraint(0, maxInt)

class MessageID(NonNegativeInteger):
    pass

class LDAPDN(LDAPString):
    # Constrained to <distinguishedName> [RFC4514]
    pass

class RelativeLDAPDN(LDAPString):
    # Constrained to <name-component> [RFC4514]
    pass

class AttributeDescription(LDAPString):
    # Constrained to <attributedescription> [RFC4512]
    pass

class AttributeValue(univ.OctetString):
    # The LDAP-specific encoding definitions for different syntaxes and
    # attribute types may be found in other documents and in particular
    # [RFC4517]
    pass

class AssertionValue(univ.OctetString):
    pass

class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', AttributeDescription()),
        namedtype.NamedType('asertionValue', AssertionValue())
    )

class SaslCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mechanism', LDAPString()),
        namedtype.OptionalNamedType('credentials', univ.OctetString())
    )

class AuthenticationChoice(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        # tags 1 and 2 are reserved
        namedtype.NamedType('sasl', SaslCredentials().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
        ))
    )

class BindRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0)
    )
    class VersionInteger(univ.Integer):
        subtypeSpec = constraint.ValueRangeConstraint(1, 127)
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', VersionInteger()),
        namedtype.NamedType('name', LDAPDN()),
        namedtype.NamedType('authentication', AuthenticationChoice())
    )

class LDAPResultCode(univ.Enumerated): # not in spec
    namedValues = namedval.NamedValues(
        ('success', 0),
        ('operationsError', 1),
        ('protocolError', 2),
        ('timeLimitExceeded', 3),
        ('sizeLimitExceeded', 4),
        ('compareFalse', 5),
        ('compareTrue', 6),
        ('authMethodNotSupported', 7),
        ('strongerAuthRequired', 8),
        # 9 reserved
        ('referral', 10),
        ('adminLimitExceeded', 11),
        ('unavailableCriticalExtension', 12),
        ('confidentialityRequired', 13),
        ('saslBindInProgress', 14),
        # 15 not mentioned in RFC
        ('noSuchAttribute', 16),
        ('undefinedAttributeType', 17),
        ('inappropriateMatching', 18),
        ('constraintViolation', 19),
        ('attributeOrValueExists', 20),
        ('invalidAttributeSyntax', 21),
        # 22-31 unused
        ('noSuchObject', 32),
        ('aliasProblem', 33),
        ('invalidDNSyntax', 34),
        # 35 reserved for undefined isLeaf
        ('aliasDereferencingProblem', 36),
        # 37-47 unused
        ('inappropriateAuthentication', 48),
        ('invalidCredentials', 49),
        ('insufficientAccessRights', 50),
        ('busy', 51),
        ('unavailable', 52),
        ('unwillingToPerform', 53),
        ('loopDetect', 54),
        # 55-63 unused
        ('namingViolation', 64),
        ('objectClassViolation', 65),
        ('notAllowedOnNonLeaf', 66),
        ('notAllowedOnRDN', 67),
        ('entryAlreadyExists', 68),
        ('objectClassModsProhibited', 69),
        # 70 reserved for CLDAP
        ('affectsMultipleDSAs', 71),
        # 72-79 unused
        ('other', 80)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
        constraint.SingleValueConstraint(0,1,2,3,4,5,6,7,8,10,11,12,13,14,16,17,18,19,20,21,32,33,34,36,48,49,50,51,52,53,54,64,65,66,67,68,69,71,80)

class URI(LDAPString):
    pass
    # limited to characters permitted in URIs

class Referral(univ.SequenceOf):
    subtypeSpec = constraint.ValueSizeConstraint(1, float('inf'))
    componentType = URI()

LDAPResultComponents = ( # Used to implement COMPONENTS OF
    namedtype.NamedType('resultCode', LDAPResultCode()),
    namedtype.NamedType('matchedDN', LDAPDN()),
    namedtype.NamedType('diagnosticMessage', LDAPString()),
    namedtype.OptionalNamedType('referral', Referral().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    ))
)

class LDAPResult(univ.Sequence):
    componentType = namedtype.NamedTypes(*LDAPResultComponents)

class BindResponse(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 1)
    )
    BindResponseComponents = LDAPResultComponents + (
        namedtype.OptionalNamedType('serverSaslCreds', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
        )),
    )
    componentType = namedtype.NamedTypes(*BindResponseComponents)

class UnbindRequest(univ.Null):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2)
    )

class SubstringFilter(univ.Sequence):
    class SeqOfSubstringChoice(NonEmptySequenceOf):
        class SubstringChoice(univ.Choice):
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('initial', AssertionValue().subtype( # can occur at most once
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                )),
                namedtype.NamedType('any', AssertionValue().subtype(
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
                )),
                namedtype.NamedType('final', AssertionValue().subtype( # can occur at most once
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
                ))
            )
        componentType = SubstringChoice()

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('substrings', SeqOfSubstringChoice())
    )

class MatchingRuleId(LDAPString):
    pass

class MatchingRuleAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('matchingRule', MatchingRuleId().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
        namedtype.OptionalNamedType('type', AttributeDescription().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )),
        namedtype.NamedType('matchValue', AssertionValue().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
        )),
        namedtype.DefaultedNamedType('dnAttributes', univ.Boolean(False).subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
        ))
    )

class Filter(univ.Choice):
    pass

class FilterSet(NonEmptySetOf): # not in spec
    componentType = Filter()

Filter.componentType = namedtype.NamedTypes(
    namedtype.NamedType('and', FilterSet().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
    )),
    namedtype.NamedType('or', FilterSet().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
    )),
    namedtype.NamedType('not', Filter().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
    )),
    namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
    )),
    namedtype.NamedType('substrings', SubstringFilter().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)
    )),
    namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5)
    )),
    namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 6)
    )),
    namedtype.NamedType('present', AttributeDescription().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)
    )),
    namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 8)
    )),
    namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 9)
    ))
)
    
class AttributeSelection(univ.SequenceOf):
    componentType = LDAPString()
    # The LDAPString is constrained to <attributeSelector> in Section 4.5.1.8

class SearchRequest(univ.Sequence):
    class ScopeEnum(univ.Enumerated):
        namedValues = namedval.NamedValues(
            ('baseObject', 0),
            ('singleLevel', 1),
            ('wholeSubtree', 2)
        )
    class DerefAliasesEnum(univ.Enumerated):
        namedValues = namedval.NamedValues(
            ('neverDerefAliases', 0),
            ('derefInSearching', 1),
            ('derefFindingBaseObj', 2),
            ('derefAlways', 3)
        )

    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 3)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('baseObject', LDAPDN()),
        namedtype.NamedType('scope', ScopeEnum()),
        namedtype.NamedType('derefAliases', DerefAliasesEnum()),
        namedtype.NamedType('sizeLimit', NonNegativeInteger()),
        namedtype.NamedType('timeLimit', NonNegativeInteger()),
        namedtype.NamedType('typesOnly', univ.Boolean()),
        namedtype.NamedType('filter', Filter()),
        namedtype.NamedType('attributes', AttributeSelection())
    )

class PartialAttribute(univ.Sequence):
    class PartialAttributeVals(univ.SetOf):
        componentType = AttributeValue()
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', PartialAttributeVals())
    )

class PartialAttributeList(univ.SequenceOf):
    componentType = PartialAttribute()

class SearchResultEntry(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 4)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('objectName', LDAPDN()),
        namedtype.NamedType('attributes', PartialAttributeList())
    )

class SearchResultDone(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 5)
    )

class SearchResultReference(NonEmptySequenceOf):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 19)
    )
    compontentType = URI()

class ModifyRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 6)
    )
    class SeqOfChange(univ.SequenceOf):
        class Change(univ.Sequence):
            class OpEnum(univ.Enumerated):
                namedValues = namedval.NamedValues(
                    ('add', 0),
                    ('delete', 1),
                    ('replace', 2)
                )
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('operation', OpEnum()),
                namedtype.NamedType('modification', PartialAttribute())
            )
        componentType = Change()
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object', LDAPDN()),
        namedtype.NamedType('changes', SeqOfChange())
    )

class ModifyResponse(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 7)
    )

class Attribute(univ.Sequence):
    class AttributeVals(NonEmptySetOf):
        componentType = AttributeValue()
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', AttributeVals())
    )

class AttributeList(univ.SequenceOf):
    componentType = Attribute()

class AddRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 8)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('attributes', AttributeList())
    )

class AddResponse(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 9)
    )

class DelRequest(LDAPDN):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10)
    )

class DelResponse(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 11)
    )

class ModifyDNRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 12)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('newrdn', RelativeLDAPDN()),
        namedtype.NamedType('deleteoldrdn', univ.Boolean()),
        namedtype.OptionalNamedType('newSuperior', LDAPDN().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )

class ModifyDNResponse(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 13)
    )

class CompareRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 14)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('ava', AttributeValueAssertion())
    )

class CompareResponse(LDAPResult):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 15)
    )

class AbandonRequest(MessageID):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 16)
    )

class ExtendedRequest(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 23)
    )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('requestName', LDAPOID().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('requestValue', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        ))
    )

class ExtendedResponse(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 24)
    )

    ExtendedResponseComponents = LDAPResultComponents + (
        namedtype.OptionalNamedType('responseName', LDAPOID().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)
        )),
        namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)
        ))
    )
    componentType = namedtype.NamedTypes(*ExtendedResponseComponents)

class IntermediateResponse(univ.Sequence):
    tagSet = tag.TagSet(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 25)
    )
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('responseName', LDAPOID().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10)
        )),
        namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)
        ))
    )
    
class ProtocolOp(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bindRequest', BindRequest()),
        namedtype.NamedType('bindResponse', BindResponse()),
        namedtype.NamedType('unbindRequest', UnbindRequest()),
        namedtype.NamedType('searchRequest', SearchRequest()),
        namedtype.NamedType('searchResEntry', SearchResultEntry()),
        namedtype.NamedType('searchResDone', SearchResultDone()),
        namedtype.NamedType('searchResRef', SearchResultReference()),
        namedtype.NamedType('modifyRequest', ModifyRequest()),
        namedtype.NamedType('modifyResponse', ModifyResponse()),
        namedtype.NamedType('addRequest', AddRequest()),
        namedtype.NamedType('addResponse', AddResponse()),
        namedtype.NamedType('delRequest', DelRequest()),
        namedtype.NamedType('delResponse', DelResponse()),
        namedtype.NamedType('modDNRequest', ModifyDNRequest()),
        namedtype.NamedType('modDNResponse', ModifyDNResponse()),
        namedtype.NamedType('compareRequest', CompareRequest()),
        namedtype.NamedType('compareResponse', CompareResponse()),
        namedtype.NamedType('abandonRequest', AbandonRequest()),
        namedtype.NamedType('extendedReq', ExtendedRequest()),
        namedtype.NamedType('extendedResp', ExtendedResponse()),
        namedtype.NamedType('intermediateResponse', IntermediateResponse())
    )

class Control(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlType', LDAPOID()),
        namedtype.DefaultedNamedType('criticality', univ.Boolean(False)),
        namedtype.OptionalNamedType('controlValue', univ.OctetString())
    )

class Controls(univ.SequenceOf):
    componentType = Control()

class LDAPMessage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', MessageID()),
        namedtype.NamedType('protocolOp', ProtocolOp()),
        namedtype.OptionalNamedType('controls', Controls().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        ))
    )
