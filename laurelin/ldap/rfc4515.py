"""PEG grammars for RFC4515"""

item = '''
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

filter = '''
      standard_filter = LPAREN filtercomp RPAREN
      filtercomp      = and / or / not / rfc4515_ava
      and             = AMPERSAND filterlist
      or              = VERTBAR filterlist
      not             = EXCLAMATION standard_filter
      filterlist      = standard_filter+
''' + item + '''
      LPAREN      = "("
      RPAREN      = ")"
      AMPERSAND   = "&"
      VERTBAR     = "|"
      EXCLAMATION = "!"
'''
