# Jesus-Centric KJV Processor

Independent modernization and Jesus-centric markup of the public-domain King James Version.

## Features
- Lexical modernization of archaic pronouns and verb forms (independent of any copyrighted translation)
- LORD and GOD rendered in ALL CAPS
- Name "Jesus" forced to JESUS (no redundant marker)
- [JESUS] marker appended to configured Messianic / Christological terms across all 66 books
- Single-pass streaming processor

## Usage
```bash
python3 jesus_centric_kjv_processor.py input_kjv.txt output.txt
```

Input should be a plain public-domain KJV text (e.g. Project Gutenberg #10900).

## Notes
- Base text is public domain. All modernization is independent lexical replacement.
- Marker application is rule-based (evangelical Messianic titles + pronouns in all books).
- Perfect theological identification of every OT reference is interpretive; the script provides a practical starting point.

## Sample (John 1:1)
```
1:1 In the beginning was the WORD[JESUS], and the WORD[JESUS] was with GOD[JESUS], and the
WORD[JESUS] was GOD[JESUS].
```
