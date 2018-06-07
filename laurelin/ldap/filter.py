"""Contains utilities for handling filters.

See RFC4515 String Representation of Search Filters
"""

from __future__ import absolute_import
from parsimonious.grammar import Grammar
from parsimonious.exceptions import ParseError
import six
from six.moves import range

from . import rfc4511
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


def escape(text):
    """Escape special characters"""
    for rep in escape_map:
        text = text.replace(*rep)
    return text


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
      standard_filter = LPAREN filtercomp RPAREN
      filtercomp      = and / or / not / rfc4515_ava
      and             = AMPERSAND filterlist
      or              = VERTBAR filterlist
      not             = EXCLAMATION standard_filter
      filterlist      = standard_filter+
''' + ava_grammar + '''
      LPAREN      = "("
      RPAREN      = ")"
      AMPERSAND   = "&"
      VERTBAR     = "|"
      EXCLAMATION = "!"
'''

_rfc4515_filter_grammar = Grammar(rfc4515_filter_grammar)


def parse_standard_filter(filter_str):
    """Parse an RFC 4515 filter string to an rfc4511.Filter"""

    try:
        filter_node = _rfc4515_filter_grammar.parse(filter_str)
        return _handle_standard_filter(filter_node)
    except ParseError as e:
        raise LDAPError(str(e))


def _handle_standard_filter(filter_node):
    fil = rfc4511.Filter()
    filtercomp = filter_node.children[1]
    for child in filtercomp.children:
        if child.expr_name == 'and':
            filterlist = child.children[1]
            and_set = rfc4511.And()
            for i, node in enumerate(filterlist.children):
                and_set.setComponentByPosition(i, _handle_standard_filter(node))
            fil.setComponentByName('and', and_set)
        elif child.expr_name == 'or':
            filterlist = child.children[1]
            or_set = rfc4511.Or()
            for i, node in enumerate(filterlist.children):
                or_set.setComponentByPosition(i, _handle_standard_filter(node))
            fil.setComponentByName('or', or_set)
        elif child.expr_name == 'not':
            node = child.children[1]
            not_filter = rfc4511.Not()
            not_filter.setComponentByName('innerNotFilter', _handle_standard_filter(node))
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
            ava = rfc4511.EqualityMatch()
        elif filtertype == "approx":
            component = 'approxMatch'
            ava = rfc4511.ApproxMatch()
        elif filtertype == "greaterorequal":
            component = 'greaterOrEqual'
            ava = rfc4511.GreaterOrEqual()
        elif filtertype == "lessorequal":
            component = 'lessOrEqual'
            ava = rfc4511.LessOrEqual()
        else:
            raise LDAPError('Unhandled condition while parsing filter')
        ava.setComponentByName('attributeDesc', rfc4511.AttributeDescription(attr_type))
        ava.setComponentByName('assertionValue', rfc4511.AssertionValue(attr_value))
        fil.setComponentByName(component, ava)
    elif ava_type.expr_name == 'substring':
        attr_type = ava_type.children[0].text

        # detect the special case that this should be rfc4511.Present
        if ava_type.children[2].text == '' and ava_type.children[3].text == '*' and ava_type.children[4].text == '':
            fil.setComponentByName('present', rfc4511.Present(attr_type))

        # standard substring
        else:
            subf = rfc4511.SubstringFilter()
            subf.setComponentByName('type', rfc4511.AttributeDescription(attr_type))
            subs = rfc4511.Substrings()
            i = 0
            if ava_type.children[2].text != '':
                c = rfc4511.Substring()
                c.setComponentByName('initial', rfc4511.Initial(ava_type.children[2].text))
                subs.setComponentByPosition(i, c)
                i += 1
            if ava_type.children[3].text != '*':
                for any_sub in ava_type.children[3].children[1].children:
                    c = rfc4511.Substring()
                    c.setComponentByName('any', rfc4511.Any(any_sub.children[0].text))
                    subs.setComponentByPosition(i, c)
                    i += 1
            if ava_type.children[4].text != '':
                c = rfc4511.Substring()
                c.setComponentByName('final', rfc4511.Final(ava_type.children[4].text))
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

        xm = rfc4511.ExtensibleMatch()
        xm.setComponentByName('matchValue', rfc4511.MatchValue(val))
        xm.setComponentByName('dnAttributes', rfc4511.DnAttributes(dnattrs))
        if attr:
            xm.setComponentByName('type', rfc4511.Type(attr))
        if rule:
            xm.setComponentByName('matchingRule', rfc4511.MatchingRule(rule))
        fil.setComponentByName('extensibleMatch', xm)
    else:
        raise LDAPError('Unhandled condition while parsing filter')


laurelin_logic_grammar = '''
    filter      = component or_exp*
    component   = term and_exp*
    or_exp      = SPACE OR SPACE component
    and_exp     = SPACE AND SPACE term
    not_exp     = NOT SPACE term
    paren_term  = "(" SPACE filter SPACE ")"
    SPACE       = ~"[ \t]*"
    OR          = "OR"
    AND         = "AND"
    NOT         = "NOT"
'''

laurelin_filter_grammar = laurelin_logic_grammar + '''
    term        = not_exp / paren_term / ava
    ava         = "(" rfc4515_ava ")"
''' + ava_grammar

_laurelin_filter_grammar = Grammar(laurelin_filter_grammar)


def parse_simple_filter(simple_filter_str):
    """Laurelin defines its own, simpler format for filter strings. It uses the
    RFC 4515 standard format for the various comparison expressions, but with
    SQL-style logic operations. (Fully standard RFC 4515 filters are fully
    supported and used by default)
    """

    try:
        filter_node = _laurelin_filter_grammar.parse(simple_filter_str)
        return _handle_simple_filter(filter_node)
    except ParseError as e:
        raise LDAPError(str(e))


def _handle_simple_filter(filter_node):
    first_component = _handle_component(filter_node.children[0])

    if filter_node.children[1].text != '':
        # got an OR
        fil = rfc4511.Filter()
        or_set = rfc4511.Or()
        i = 0
        or_set.setComponentByPosition(i, first_component)
        i += 1
        or_exps = filter_node.children[1].children
        for or_exp in or_exps:
            or_component = or_exp.children[3]
            or_set.setComponentByPosition(i, _handle_component(or_component))
            i += 1
        fil.setComponentByName('or', or_set)
    else:
        # got a single component
        fil = first_component
    return fil


def _handle_component(component_node):
    term_node = component_node.children[0]
    first_term = _handle_term(term_node)
    if component_node.children[1].text != '':
        # got AND terms
        fil = rfc4511.Filter()
        and_set = rfc4511.And()
        i = 0
        and_set.setComponentByPosition(i, first_term)
        i += 1
        for and_exp in component_node.children[1].children:
            and_set.setComponentByPosition(i, _handle_term(and_exp.children[3]))
            i += 1
        fil.setComponentByName('and', and_set)
    else:
        # got a single term
        fil = first_term
    return fil


def _handle_term(term_node):
    term_type = term_node.children[0]
    if term_type.expr_name == 'not_exp':
        fil = rfc4511.Filter()
        not_filter = rfc4511.Not()
        not_filter.setComponentByName('innerNotFilter', _handle_term(term_type.children[2]))
        fil.setComponentByName('not', not_filter)
    elif term_type.expr_name == 'paren_term':
        fil = _handle_simple_filter(term_type.children[2])

    # support both simple and unified grammar
    elif term_type.expr_name == 'ava':
        fil = rfc4511.Filter()
        _handle_rfc4515_ava(fil, term_type.children[1])
    elif term_type.expr_name == 'standard_filter':
        fil = _handle_standard_filter(term_type)

    else:
        raise LDAPError('Unhandled condition while parsing filter')
    return fil


unified_filter_grammar = laurelin_logic_grammar + '''
    term        = not_exp / paren_term / standard_filter
''' + rfc4515_filter_grammar

_unified_filter_grammar = Grammar(unified_filter_grammar)


def parse(filter_str):
    """Parse unified filter syntax. Fully compatible with standard filters, laurelin simple filters, and any
    intermingling of the two.
    """

    try:
        filter_node = _unified_filter_grammar.parse(filter_str)
        return _handle_simple_filter(filter_node)
    except ParseError as e:
        raise LDAPError(str(e))


def rfc4511_filter_to_rfc4515_string(fil):
    """Reverse :func:`parse_standard_filter`, mainly used for testing

    :param Filter fil: An rfc4511.Filter object
    :return: An RFC 4515 compatible filter string
    """
    filter_type = fil.getName()
    if filter_type == 'and':
        and_obj = fil.getComponent()
        ret = '(&{0})'.format(_reverse_filterset(and_obj))
    elif filter_type == 'or':
        or_obj = fil.getComponent()
        ret = '(|{0})'.format(_reverse_filterset(or_obj))
    elif filter_type == 'not':
        not_obj = fil.getComponent()
        not_filter = not_obj.getComponentByName('innerNotFilter')
        ret = '(!{0})'.format(rfc4511_filter_to_rfc4515_string(not_filter))
    elif filter_type == 'equalityMatch':
        ava = fil.getComponent()
        ret = '({0}={1})'.format(six.text_type(ava.getComponentByName('attributeDesc')),
                                 six.text_type(ava.getComponentByName('assertionValue')))
    elif filter_type == 'substrings':
        subs_obj = fil.getComponent()
        attr_type = six.text_type(subs_obj.getComponentByName('type'))
        subs = subs_obj.getComponentByName('substrings')
        n = len(subs)
        sub_name = ''
        sub_strs = []
        first_type = subs.getComponentByPosition(0).getName()
        if first_type != 'initial':
            sub_strs.append('')
        for i in range(n):
            sub_obj = subs.getComponentByPosition(i)
            sub_name = sub_obj.getName()
            sub_str = six.text_type(sub_obj.getComponent())
            sub_strs.append(sub_str)
        if sub_name != 'final' and sub_strs[-1] != '':
            sub_strs.append('')
        ret = '({0}={1})'.format(attr_type, '*'.join(sub_strs))
    elif filter_type == 'greaterOrEqual':
        ava = fil.getComponent()
        ret = '({0}>={1})'.format(six.text_type(ava.getComponentByName('attributeDesc')),
                                  six.text_type(ava.getComponentByName('assertionValue')))
    elif filter_type == 'lessOrEqual':
        ava = fil.getComponent()
        ret = '({0}<={1})'.format(six.text_type(ava.getComponentByName('attributeDesc')),
                                  six.text_type(ava.getComponentByName('assertionValue')))
    elif filter_type == 'present':
        present_obj = fil.getComponent()
        attr_type = six.text_type(present_obj)
        ret = '({0}=*)'.format(attr_type)
    elif filter_type == 'approxMatch':
        ava = fil.getComponent()
        ret = '({0}~={1})'.format(six.text_type(ava.getComponentByName('attributeDesc')),
                                  six.text_type(ava.getComponentByName('assertionValue')))
    elif filter_type == 'extensibleMatch':
        xm_obj = fil.getComponent()

        rule = ''
        rule_obj = xm_obj.getComponentByName('matchingRule')
        if rule_obj.isValue:
            rule = ':' + six.text_type(rule_obj)

        attr = ''
        attr_obj = xm_obj.getComponentByName('type')
        if attr_obj.isValue:
            attr = six.text_type(attr_obj)

        dn_attrs = ':dn' if bool(xm_obj.getComponentByName('dnAttributes')) else ''

        value = six.text_type(xm_obj.getComponentByName('matchValue'))

        ret = '({0}{1}{2}:={3})'.format(attr, dn_attrs, rule, value)
    else:
        raise LDAPError('Unhandled condition while constructing filter string')
    return ret


def _reverse_filterset(filterset):
    n = len(filterset)
    ret = ''
    for i in range(n):
        ret += rfc4511_filter_to_rfc4515_string(filterset.getComponentByPosition(i))
    return ret
