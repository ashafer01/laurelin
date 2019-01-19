PrintableCharacter = r"[A-Za-z0-9'()+,.=/:? -]"
PrintableString = PrintableCharacter + r'+'

IA5String = r"[\x00-\x7f]*"
BitString = r"'[01]*'B"
