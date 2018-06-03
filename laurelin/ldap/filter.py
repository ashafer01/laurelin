"""Contains utilities for handling filters.

See RFC4515 String Representation of Search Filters
"""

from __future__ import absolute_import
from parsimonious.grammar import Grammar
from parsimonious.exceptions import ParseError
from .rfc4511 import (
    Filter,
    And,
    Or,
    Not,
    EqualityMatch,
    SubstringFilter,
    GreaterOrEqual,
    LessOrEqual,
    Present,
    ApproxMatch,
    AttributeDescription,
    Substrings,
    Substring,
    AssertionValue,
    Initial,
    Any,
    Final,
    ExtensibleMatch,
    MatchValue,
    MatchingRule,
    DnAttributes,
    Type,
)
from .exceptions import LDAPError

escape_map = [
    ('(', '\\28'),
    (')', '\\29'),
    ('&', '\\26'),
    ('|', '\\7c'),
    ('!', '\\21'),
    ('=', '\\3d'),
    ('<', '\\3c'),
    ('>', '\\3e'),
    ('~', '\\7e'),
    ('*', '\\2a'),
    ('/', '\\2f')
]

ava_grammar = '''
      rfc4515_ava    = substring / simple / extensible
      simple         = attr filtertype assertionvalue
      filtertype     = approx / greaterorequal / lessorequal / equal
      equal          = EQUALS
      approx         = TILDE EQUALS
      greaterorequal = RANGLE EQUALS
      lessorequal    = LANGLE EQUALS
      extensible     = ( ( attr dnattrs? matchingrule? COLON EQUALS assertionvalue )
                       / ( dnattrs? matchingrule COLON EQUALS assertionvalue ) )
      substring      = attr EQUALS initial? any final?
      initial        = assertionvalue
      any            = ASTERISK (assertionvalue ASTERISK)*
      final          = assertionvalue
      attr           = attributedescription

      attributedescription = attributetype options
      attributetype        = oid
      options              = ( SEMI option )*
      option               = keychar+

      dnattrs        = COLON "dn"
      matchingrule   = COLON oid

      oid = descr / numericoid

      numericoid = number ( DOT number )+
      number     = DIGIT / ( LDIGIT DIGIT+ )
      DIGIT      = ~r"[0-9]"
      LDIGIT     = ~r"[1-9]"

      descr       = keystring
      keystring   = leadkeychar keychar*
      leadkeychar = ALPHA
      keychar     = ALPHA / DIGIT / HYPHEN
      ALPHA       = ~r"[A-Za-z]"

      assertionvalue = valueencoding
      valueencoding  = (normal / escaped)*
      normal         = ~r"[^\\0()*\\\\]"
      escaped        = ESC HEX HEX
      HEX            = DIGIT / ~r"[A-Fa-f]"

      EQUALS   = "="
      TILDE    = "~"
      LANGLE   = "<"
      RANGLE   = ">"
      COLON    = ":"
      ASTERISK = "*"
      DOT      = "."
      HYPHEN   = "-"
      SEMI     = ";"
      ESC      = "\\\\"
'''

rfc4515_filter_grammar = '''
      filter         = LPAREN filtercomp RPAREN
      filtercomp     = and / or / not / rfc4515_ava
      and            = AMPERSAND filterlist
      or             = VERTBAR filterlist
      not            = EXCLAMATION filter
      filterlist     = filter+
''' + ava_grammar + '''
      LPAREN      = "("
      RPAREN      = ")"
      AMPERSAND   = "&"
      VERTBAR     = "|"
      EXCLAMATION = "!"
'''

_rfc4515_filter_grammar = Grammar(rfc4515_filter_grammar)


def escape(text):
    """Escape special characters"""
    for rep in escape_map:
        text = text.replace(*rep)
    return text


def parse(filter_str):
    """Parse an RFC 4515 filter string to an rfc4515.Filter"""

    try:
        filter_node = _rfc4515_filter_grammar.parse(filter_str)
        return _handle_filter(filter_node)
    except ParseError as e:
        raise LDAPError(str(e))


def _handle_filter(filter_node):
    fil = Filter()
    filtercomp = filter_node.children[1]
    for child in filtercomp.children:
        if child.expr_name == 'and':
            filterlist = child.children[1]
            and_set = And()
            for i, node in enumerate(filterlist.children):
                and_set.setComponentByPosition(i, _handle_filter(node))
            fil.setComponentByName('and', and_set)
        elif child.expr_name == 'or':
            filterlist = child.children[1]
            or_set = Or()
            for i, node in enumerate(filterlist.children):
                or_set.setComponentByPosition(i, _handle_filter(node))
            fil.setComponentByName('or', or_set)
        elif child.expr_name == 'not':
            node = child.children[1]
            not_filter = Not()
            not_filter.setComponentByName('innerNotFilter', _handle_filter(node))
            fil.setComponentByName('not', not_filter)
        elif child.expr_name == 'rfc4515_ava':
            _handle_rfc4515_ava(fil, child)
        else:
            raise LDAPError('Unhandled condition while parsing filter')
    return fil


def _handle_rfc4515_ava(fil, ava_node):
    ava_type = ava_node.children[0]
    if ava_type.expr_name == 'simple':
        attr_type = ava_type.children[0].text
        filtertype = ava_type.children[1].children[0].expr_name
        attr_value = ava_type.children[2].text
        if filtertype == "EQUALS":
            component = 'equalityMatch'
            ava = EqualityMatch()
        elif filtertype == "approx":
            component = 'approxMatch'
            ava = ApproxMatch()
        elif filtertype == "greaterorequal":
            component = 'greaterOrEqual'
            ava = GreaterOrEqual()
        elif filtertype == "lessorequal":
            component = 'lessOrEqual'
            ava = LessOrEqual()
        else:
            raise LDAPError('Unhandled condition while parsing filter')
        ava.setComponentByName('attributeDesc', AttributeDescription(attr_type))
        ava.setComponentByName('assertionValue', AssertionValue(attr_value))
        fil.setComponentByName(component, ava)
    elif ava_type.expr_name == 'substring':
        attr_type = ava_type.children[0].text

        # detect the special case that this should be rfc4511.Present
        if ava_type.children[2].text == '' and ava_type.children[3].text == '*' and ava_type.children[4].text == '':
            fil.setComponentByName('present', Present(attr_type))

        # standard substring
        else:
            subf = SubstringFilter()
            subf.setComponentByName('type', AttributeDescription(attr_type))
            subs = Substrings()
            i = 0
            if ava_type.children[2].text != '':
                c = Substring()
                c.setComponentByName('initial', Initial(ava_type.children[2].text))
                subs.setComponentByPosition(i, c)
                i += 1
            if ava_type.children[3].text != '*':
                for any_sub in ava_type.children[3].children[1:]:
                    c = Substring()
                    c.setComponentByName('any', Any(any_sub.children[0].text))
                    subs.setComponentByPosition(i, c)
                    i += 1
            if ava_type.children[4].text != '':
                c = Substring()
                c.setComponentByName('final', Final(ava_type.children[4].text))
                subs.setComponentByPosition(i, c)
            subf.setComponentByName('substrings', subs)
            fil.setComponentByName('substrings', subf)
    elif ava_type.expr_name == 'extensible':
        ext_filter = ava_type.children[0]

        num_children = len(ext_filter.children)
        if num_children == 6:
            attr = ext_filter.children[0].text
            dnattrs = (ext_filter.children[1].text == ':dn')
            rule = ext_filter.children[2].text[1:]
            val = ext_filter.children[5].text
        elif num_children == 5:
            attr = None
            dnattrs = (ext_filter.children[0].text == ':dn')
            rule = ext_filter.children[1].text[1:]
            val = ext_filter.children[4].text
        else:
            raise LDAPError('Unhandled condition while parsing filter')

        xm = ExtensibleMatch()
        xm.setComponentByName('matchValue', MatchValue(val))
        xm.setComponentByName('dnAttributes', DnAttributes(dnattrs))
        if attr:
            xm.setComponentByName('type', Type(attr))
        if rule:
            xm.setComponentByName('matchingRule', MatchingRule(rule))
        fil.setComponentByName('extensibleMatch', xm)
    else:
        raise LDAPError('Unhandled condition while parsing filter')


def parse_simple_filter(simple_filter_str):
    """Laurelin defines its own, simpler format for filter strings. It uses the
    RFC 4515 standard format for the various comparison expressions, but with
    SQL-style logic operations. (Fully standard RFC 4515 filters are fully
    supported and used by default)
    """

    grammar = par.Grammar('''
            filter      = component or_exp*
            component   = term and_exp*
            or_exp      = SPACE OR SPACE component
            and_exp     = SPACE AND SPACE term
            term        = (NOT SPACE term) / paren_term / rfc4515_ava
            paren_term  = "(" SPACE filter SPACE ")"

            SPACE       = ~"[ \t]*"
            OR          = "OR"
            AND         = "AND"
            NOT         = "NOT"
            rfc4515_ava = "AVA"
            ''')

    grammar.parse(simple_filter_str)
