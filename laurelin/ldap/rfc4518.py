"""RFC 4518: Internationalized String Preparation

https://tools.ietf.org/html/rfc4518
"""

from __future__ import absolute_import

from . import utils
from .exceptions import ProhibitedCharacterError, LDAPUnicodeWarning

import re
import sys
from unicodedata import normalize
from warnings import warn

if sys.maxunicode >= 1114111:
    UCS = 4
else:
    warn('This python build only supports unicode code points up to {0} - string '
         'preparation will not be fully compliant with RFC4518'.format(sys.maxunicode),
         LDAPUnicodeWarning)
    UCS = 2


def Transcode(value):
    try:
        if not isinstance(value, unicode):
            return unicode(value)
    except NameError:
        if not isinstance(value, str):
            return str(value)
    return value


if UCS == 4:
    _map_nothing = re.compile(
        u'[\u00AD\u1806\u034F\u180B-\u180D\uFE00-\uFE0F\uFFFC\u0000-\u0008\u000E-\u001F'
        u'\u007F-\u0084\u0086-\u009F\u06DD\u070F\u180E\u200B-\u200F\u202A-\u202E'
        u'\u2060-\u2063\u206A-\u206F\uFEFF\uFFF9-\uFFFB\U0001D173-\U0001D17A\U000E0001'
        u'\U000E0020-\U000E007F]'
    )
else:
    _map_nothing = re.compile(
        u'[\u00AD\u1806\u034F\u180B-\u180D\uFE00-\uFE0F\uFFFC\u0000-\u0008\u000E-\u001F'
        u'\u007F-\u0084\u0086-\u009F\u06DD\u070F\u180E\u200B-\u200F\u202A-\u202E'
        u'\u2060-\u2063\u206A-\u206F\uFEFF\uFFF9-\uFFFB]'
    )

_map_space = re.compile(
    u'[\u0009-\u000D\u0085\u0020\u00A0\u1680\u2000-\u200A\u2028-\u2029\u202F\u205F\u3000]'
)


class Map:
    @staticmethod
    def characters(value):
        value = _map_nothing.sub('', value)
        value = _map_space.sub(' ', value)
        return value

    @staticmethod
    def casefold(value):
        value = utils.casefold(value)
        return value

    @staticmethod
    def all(value):
        value = Map.characters(value)
        value = Map.casefold(value)
        return value


def Normalize(value):
    return normalize('NFKC', value)


# prohibited code points per RFC 4518 from various tables in RFC 3454
if UCS == 4:
    _prohibited = re.compile(
        u'[\u0221\u0234-\u024F\u02AE-\u02AF\u02EF-\u02FFF\u0370-\u0373\u0376-\u0379'
        u'\u037B-\u037D\u037F-\u0383\u038B\u038D\u03A2\u03CF\u03F7-\u03FF\u0487\u04CF'
        u'\u04F6-\u04F7\u04FA-\u04FF\u0510-\u0530\u0557-\u0558\u0560\u0588\u058B-\u0590'
        u'\u05A2\u05BA\u05C5-\u05CF\u05EB-\u05EF\u05F5-\u060B\u060D-\u061A\u061C-\u061E'
        u'\u0620\u063B-\u063F\u0656-\u065F\u06EE-\u06EF\u06FF\u070E\u072D-\u072F'
        u'\u074B-\u077F\u07B2-\u0900\u0904\u093A-\u093B\u094E-\u094F\u0955-\u0957'
        u'\u0971-\u0980\u0984\u098D-\u098E\u0991-\u0992\u09A9\u09B1\u09B3-\u09B5'
        u'\u09BA-\u09BB\u09BD\u09C5-\u09C6\u09C9-\u09CA\u09CE-\u09D6\u09D8-\u09DB\u09DE'
        u'\u09E4-\u09E5\u09FB-\u0A01\u0A03-\u0A04\u0A0B-\u0A0E\u0A11-\u0A12\u0A29\u0A31'
        u'\u0A34\u0A37\u0A3A-\u0A3B\u0A3D\u0A43-\u0A46\u0A49-\u0A4A\u0A4E-\u0A58\u0A5D'
        u'\u0A5F-\u0A65\u0A75-\u0A80\u0A84\u0A8C\u0A8E\u0A92\u0AA9\u0AB1\u0AB4'
        u'\u0ABA-\u0ABB\u0AC6\u0ACA\u0ACE-\u0ACF\u0AD1-\u0ADF\u0AE1-\u0AE5\u0AF0-\u0B00'
        u'\u0B04\u0B0D-\u0B0E\u0B11-\u0B12\u0B29\u0B31\u0B34-\u0B35\u0B3A-\u0B3B'
        u'\u0B44-\u0B46\u0B49-\u0B4A\u0B4E-\u0B55\u0B58-\u0B5B\u0B5E\u0B62-\u0B65'
        u'\u0B71-\u0B81\u0B84\u0B8B-\u0B8D\u0B91\u0B96-\u0B98\u0B9B\u0B9D\u0BA0-\u0BA2'
        u'\u0BA5-\u0BA7\u0BAB-\u0BAD\u0BB6\u0BBA-\u0BBD\u0BC3-\u0BC5\u0BC9\u0BCE-\u0BD6'
        u'\u0BD8-\u0BE6\u0BF3-\u0C00\u0C04\u0C0D\u0C11\u0C29\u0C34\u0C3A-\u0C3D\u0C45'
        u'\u0C49\u0C4E-\u0C54\u0C57-\u0C5F\u0C62-\u0C65\u0C70-\u0C81\u0C84\u0C8D\u0C91'
        u'\u0CA9\u0CB4\u0CBA-\u0CBD\u0CC5\u0CC9\u0CCE-\u0CD4\u0CD7-\u0CDD\u0CDF\u0CE2-\u0CE5'
        u'\u0CF0-\u0D01\u0D04\u0D0D\u0D11\u0D29\u0D3A-\u0D3D\u0D44-\u0D45\u0D49\u0D4E-\u0D56'
        u'\u0D58-\u0D5F\u0D62-\u0D65\u0D70-\u0D81\u0D84\u0D97-\u0D99\u0DB2\u0DBC'
        u'\u0DBE-\u0DBF\u0DC7-\u0DC9\u0DCB-\u0DCE\u0DD5\u0DD7\u0DE0-\u0DF1\u0DF5-\u0E00'
        u'\u0E3B-\u0E3E\u0E5C-\u0E80\u0E83\u0E85-\u0E86\u0E89\u0E8B-\u0E8C\u0E8E-\u0E93'
        u'\u0E98\u0EA0\u0EA4\u0EA6\u0EA8-\u0EA9\u0EAC\u0EBA\u0EBE-\u0EBF\u0EC5\u0EC7'
        u'\u0ECE-\u0ECF\u0EDA-\u0EDB\u0EDE-\u0EFF\u0F48\u0F6B-\u0F70\u0F8C-\u0F8F\u0F98'
        u'\u0FBD\u0FCD-\u0FCE\u0FD0-\u0FFF\u1022\u1028\u102B\u1033-\u1035\u103A-\u103F'
        u'\u105A-\u109F\u10C6-\u10CF\u10F9-\u10FA\u10FC-\u10FF\u115A-\u115E\u11A3-\u11A7'
        u'\u11FA-\u11FF\u1207\u1247\u1249\u124E-\u124F\u1257\u1259\u125E-\u125F\u1287\u1289'
        u'\u128E-\u128F\u12AF\u12B1\u12B6-\u12B7\u12BF\u12C1\u12C6-\u12C7\u12CF\u12D7\u12EF'
        u'\u130F\u1311\u1316-\u1317\u131F\u1347\u135B-\u1360\u137D-\u139F\u13F5-\u1400'
        u'\u1677-\u167F\u169D-\u169F\u16F1-\u16FF\u170D\u1715-\u171F\u1737-\u173F'
        u'\u1754-\u175F\u176D\u1771\u1774-\u177F\u17DD-\u17DF\u17EA-\u17FF\u180F'
        u'\u181A-\u181F\u1878-\u187F\u18AA-\u1DFF\u1E9C-\u1E9F\u1EFA-\u1EFF\u1F16-\u1F17'
        u'\u1F1E-\u1F1F\u1F46-\u1F47\u1F4E-\u1F4F\u1F58\u1F5A\u1F5C\u1F5E\u1F7E-\u1F7F'
        u'\u1FB5\u1FC5\u1FD4-\u1FD5\u1FDC\u1FF0-\u1FF1\u1FF5\u1FFF\u2053-\u2056\u2058-\u205E'
        u'\u2064-\u2069\u2072-\u2073\u208F-\u209F\u20B2-\u20CF\u20EB-\u20FF\u213B-\u213C'
        u'\u214C-\u2152\u2184-\u218F\u23CF-\u23FF\u2427-\u243F\u244B-\u245F\u24FF'
        u'\u2614-\u2615\u2618\u267E-\u267F\u268A-\u2700\u2705\u270A-\u270B\u2728\u274C\u274E'
        u'\u2753-\u2755\u2757\u275F-\u2760\u2795-\u2797\u27B0\u27BF-\u27CF\u27EC-\u27EF'
        u'\u2B00-\u2E7F\u2E9A\u2EF4-\u2EFF\u2FD6-\u2FEF\u2FFC-\u2FFF\u3040\u3097-\u3098'
        u'\u3100-\u3104\u312D-\u3130\u318F\u31B8-\u31EF\u321D-\u321F\u3244-\u3250'
        u'\u327C-\u327E\u32CC-\u32CF\u32FF\u3377-\u337A\u33DE-\u33DF\u33FF\u4DB6-\u4DFF'
        u'\u9FA6-\u9FFF\uA48D-\uA48F\uA4C7-\uABFF\uD7A4-\uD7FF\uFA2E-\uFA2F\uFA6B-\uFAFF'
        u'\uFB07-\uFB12\uFB18-\uFB1C\uFB37\uFB3D\uFB3F\uFB42\uFB45\uFBB2-\uFBD2\uFD40-\uFD4F'
        u'\uFD90-\uFD91\uFDC8-\uFDCF\uFDFD-\uFDFF\uFE10-\uFE1F\uFE24-\uFE2F\uFE47-\uFE48'
        u'\uFE53\uFE67\uFE6C-\uFE6F\uFE75\uFEFD-\uFEFE\uFF00\uFFBF-\uFFC1\uFFC8-\uFFC9'
        u'\uFFD0-\uFFD1\uFFD8-\uFFD9\uFFDD-\uFFDF\uFFE7\uFFEF-\uFFF8\U00010000-\U000102FF'
        u'\U0001031F\U00010324-\U0001032F\U0001034B-\U000103FF\U00010426-\U00010427'
        u'\U0001044E-\U0001CFFF\U0001D0F6-\U0001D0FF\U0001D127-\U0001D129'
        u'\U0001D1DE-\U0001D3FF\U0001D455\U0001D49D\U0001D4A0-\U0001D4A1'
        u'\U0001D4A3-\U0001D4A4\U0001D4A7-\U0001D4A8\U0001D4AD\U0001D4BA\U0001D4BC'
        u'\U0001D4C1\U0001D4C4\U0001D506\U0001D50B-\U0001D50C\U0001D515\U0001D51D\U0001D53A'
        u'\U0001D53F\U0001D545\U0001D547-\U0001D549\U0001D551\U0001D6A4-\U0001D6A7'
        u'\U0001D7CA-\U0001D7CD\U0001D800-\U0001FFFD\U0002A6D7-\U0002F7FF'
        u'\U0002FA1E-\U0002FFFD\U00030000-\U0003FFFD\U00040000-\U0004FFFD'
        u'\U00050000-\U0005FFFD\U00060000-\U0006FFFD\U00070000-\U0007FFFD'
        u'\U00080000-\U0008FFFD\U00090000-\U0009FFFD\U000A0000-\U000AFFFD'
        u'\U000B0000-\U000BFFFD\U000C0000-\U000CFFFD\U000D0000-\U000DFFFD\U000E0000'
        u'\U000E0002-\U000E001F\U000E0080-\U000EFFFD\u0340\u0341\u200E\u200F\u202A\u202B'
        u'\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F\uE000-\uF8FF'
        u'\U000F0000-\U000FFFFD\U00100000-\U0010FFFD\uFDD0-\uFDEF\uFFFE-\uFFFF'
        u'\U0001FFFE-\U0001FFFF\U0002FFFE-\U0002FFFF\U0003FFFE-\U0003FFFF'
        u'\U0004FFFE-\U0004FFFF\U0005FFFE-\U0005FFFF\U0006FFFE-\U0006FFFF'
        u'\U0007FFFE-\U0007FFFF\U0008FFFE-\U0008FFFF\U0009FFFE-\U0009FFFF'
        u'\U000AFFFE-\U000AFFFF\U000BFFFE-\U000BFFFF\U000CFFFE-\U000CFFFF'
        u'\U000DFFFE-\U000DFFFF\U000EFFFE-\U000EFFFF\U000FFFFE-\U000FFFFF'
        u'\U0010FFFE-\U0010FFFF\uD800-\uDFFF\uFFFD]'
    )
else:
    _prohibited = re.compile(
        u'[\u0221\u0234-\u024F\u02AE-\u02AF\u02EF-\u02FFF\u0370-\u0373\u0376-\u0379'
        u'\u037B-\u037D\u037F-\u0383\u038B\u038D\u03A2\u03CF\u03F7-\u03FF\u0487\u04CF'
        u'\u04F6-\u04F7\u04FA-\u04FF\u0510-\u0530\u0557-\u0558\u0560\u0588\u058B-\u0590'
        u'\u05A2\u05BA\u05C5-\u05CF\u05EB-\u05EF\u05F5-\u060B\u060D-\u061A\u061C-\u061E'
        u'\u0620\u063B-\u063F\u0656-\u065F\u06EE-\u06EF\u06FF\u070E\u072D-\u072F'
        u'\u074B-\u077F\u07B2-\u0900\u0904\u093A-\u093B\u094E-\u094F\u0955-\u0957'
        u'\u0971-\u0980\u0984\u098D-\u098E\u0991-\u0992\u09A9\u09B1\u09B3-\u09B5'
        u'\u09BA-\u09BB\u09BD\u09C5-\u09C6\u09C9-\u09CA\u09CE-\u09D6\u09D8-\u09DB\u09DE'
        u'\u09E4-\u09E5\u09FB-\u0A01\u0A03-\u0A04\u0A0B-\u0A0E\u0A11-\u0A12\u0A29\u0A31'
        u'\u0A34\u0A37\u0A3A-\u0A3B\u0A3D\u0A43-\u0A46\u0A49-\u0A4A\u0A4E-\u0A58\u0A5D'
        u'\u0A5F-\u0A65\u0A75-\u0A80\u0A84\u0A8C\u0A8E\u0A92\u0AA9\u0AB1\u0AB4'
        u'\u0ABA-\u0ABB\u0AC6\u0ACA\u0ACE-\u0ACF\u0AD1-\u0ADF\u0AE1-\u0AE5\u0AF0-\u0B00'
        u'\u0B04\u0B0D-\u0B0E\u0B11-\u0B12\u0B29\u0B31\u0B34-\u0B35\u0B3A-\u0B3B'
        u'\u0B44-\u0B46\u0B49-\u0B4A\u0B4E-\u0B55\u0B58-\u0B5B\u0B5E\u0B62-\u0B65'
        u'\u0B71-\u0B81\u0B84\u0B8B-\u0B8D\u0B91\u0B96-\u0B98\u0B9B\u0B9D\u0BA0-\u0BA2'
        u'\u0BA5-\u0BA7\u0BAB-\u0BAD\u0BB6\u0BBA-\u0BBD\u0BC3-\u0BC5\u0BC9\u0BCE-\u0BD6'
        u'\u0BD8-\u0BE6\u0BF3-\u0C00\u0C04\u0C0D\u0C11\u0C29\u0C34\u0C3A-\u0C3D\u0C45'
        u'\u0C49\u0C4E-\u0C54\u0C57-\u0C5F\u0C62-\u0C65\u0C70-\u0C81\u0C84\u0C8D\u0C91'
        u'\u0CA9\u0CB4\u0CBA-\u0CBD\u0CC5\u0CC9\u0CCE-\u0CD4\u0CD7-\u0CDD\u0CDF\u0CE2-\u0CE5'
        u'\u0CF0-\u0D01\u0D04\u0D0D\u0D11\u0D29\u0D3A-\u0D3D\u0D44-\u0D45\u0D49\u0D4E-\u0D56'
        u'\u0D58-\u0D5F\u0D62-\u0D65\u0D70-\u0D81\u0D84\u0D97-\u0D99\u0DB2\u0DBC'
        u'\u0DBE-\u0DBF\u0DC7-\u0DC9\u0DCB-\u0DCE\u0DD5\u0DD7\u0DE0-\u0DF1\u0DF5-\u0E00'
        u'\u0E3B-\u0E3E\u0E5C-\u0E80\u0E83\u0E85-\u0E86\u0E89\u0E8B-\u0E8C\u0E8E-\u0E93'
        u'\u0E98\u0EA0\u0EA4\u0EA6\u0EA8-\u0EA9\u0EAC\u0EBA\u0EBE-\u0EBF\u0EC5\u0EC7'
        u'\u0ECE-\u0ECF\u0EDA-\u0EDB\u0EDE-\u0EFF\u0F48\u0F6B-\u0F70\u0F8C-\u0F8F\u0F98'
        u'\u0FBD\u0FCD-\u0FCE\u0FD0-\u0FFF\u1022\u1028\u102B\u1033-\u1035\u103A-\u103F'
        u'\u105A-\u109F\u10C6-\u10CF\u10F9-\u10FA\u10FC-\u10FF\u115A-\u115E\u11A3-\u11A7'
        u'\u11FA-\u11FF\u1207\u1247\u1249\u124E-\u124F\u1257\u1259\u125E-\u125F\u1287\u1289'
        u'\u128E-\u128F\u12AF\u12B1\u12B6-\u12B7\u12BF\u12C1\u12C6-\u12C7\u12CF\u12D7\u12EF'
        u'\u130F\u1311\u1316-\u1317\u131F\u1347\u135B-\u1360\u137D-\u139F\u13F5-\u1400'
        u'\u1677-\u167F\u169D-\u169F\u16F1-\u16FF\u170D\u1715-\u171F\u1737-\u173F'
        u'\u1754-\u175F\u176D\u1771\u1774-\u177F\u17DD-\u17DF\u17EA-\u17FF\u180F'
        u'\u181A-\u181F\u1878-\u187F\u18AA-\u1DFF\u1E9C-\u1E9F\u1EFA-\u1EFF\u1F16-\u1F17'
        u'\u1F1E-\u1F1F\u1F46-\u1F47\u1F4E-\u1F4F\u1F58\u1F5A\u1F5C\u1F5E\u1F7E-\u1F7F'
        u'\u1FB5\u1FC5\u1FD4-\u1FD5\u1FDC\u1FF0-\u1FF1\u1FF5\u1FFF\u2053-\u2056\u2058-\u205E'
        u'\u2064-\u2069\u2072-\u2073\u208F-\u209F\u20B2-\u20CF\u20EB-\u20FF\u213B-\u213C'
        u'\u214C-\u2152\u2184-\u218F\u23CF-\u23FF\u2427-\u243F\u244B-\u245F\u24FF'
        u'\u2614-\u2615\u2618\u267E-\u267F\u268A-\u2700\u2705\u270A-\u270B\u2728\u274C\u274E'
        u'\u2753-\u2755\u2757\u275F-\u2760\u2795-\u2797\u27B0\u27BF-\u27CF\u27EC-\u27EF'
        u'\u2B00-\u2E7F\u2E9A\u2EF4-\u2EFF\u2FD6-\u2FEF\u2FFC-\u2FFF\u3040\u3097-\u3098'
        u'\u3100-\u3104\u312D-\u3130\u318F\u31B8-\u31EF\u321D-\u321F\u3244-\u3250'
        u'\u327C-\u327E\u32CC-\u32CF\u32FF\u3377-\u337A\u33DE-\u33DF\u33FF\u4DB6-\u4DFF'
        u'\u9FA6-\u9FFF\uA48D-\uA48F\uA4C7-\uABFF\uD7A4-\uD7FF\uFA2E-\uFA2F\uFA6B-\uFAFF'
        u'\uFB07-\uFB12\uFB18-\uFB1C\uFB37\uFB3D\uFB3F\uFB42\uFB45\uFBB2-\uFBD2\uFD40-\uFD4F'
        u'\uFD90-\uFD91\uFDC8-\uFDCF\uFDFD-\uFDFF\uFE10-\uFE1F\uFE24-\uFE2F\uFE47-\uFE48'
        u'\uFE53\uFE67\uFE6C-\uFE6F\uFE75\uFEFD-\uFEFE\uFF00\uFFBF-\uFFC1\uFFC8-\uFFC9'
        u'\uFFD0-\uFFD1\uFFD8-\uFFD9\uFFDD-\uFFDF\uFFE7\uFFEF-\uFFF8\u0340\u0341\u200E'
        u'\u200F\u202A\u202B\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F'
        u'\uE000-\uF8FF\uFDD0-\uFDEF\uFFFE-\uFFFF\uD800-\uDFFF\uFFFD]'
    )


def Prohibit(value):
    if _prohibited.match(value):
        raise ProhibitedCharacterError()
    return value


class Insignificant:
    @staticmethod
    def space(value):
        value = value.strip()
        value = re.sub(' +', '  ', value)
        value = u' {0} '.format(value)
        return value

    @staticmethod
    def numeric_string(value):
        value = re.sub(' +', '', value)
        return value

    @staticmethod
    def telephone_number(value):
        value = re.sub(u'[ \u002D\u058A\u2010\u2011\u2212\uFE63\uFF0D]', '', value)
        return value
