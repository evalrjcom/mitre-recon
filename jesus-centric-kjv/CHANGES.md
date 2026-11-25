# Changes Applied

Source: Project Gutenberg eBook #10900 (The King James Bible, Complete) — public domain.

## Rules applied by the processor
- Independent lexical modernization (thee/thou/ye → you, -eth verbs updated, obsolete words clarified)
- Lord/God → LORD/GOD
- Jesus → JESUS (no redundant marker)
- [JESUS] marker on configured Messianic terms and pronouns across all 66 books
- Terms marked: He/Him/His, LORD, GOD, Son of Man, Son of God, Christ, Messiah, Word, Lamb, Son, Branch, Servant, Shepherd, Seed, Shiloh, Star, Prophet, Immanuel, Wonderful, Counsellor, Prince of Peace, Root, Offspring, King

## Files
- `input/kjv_gutenberg_10900.txt` — original public-domain source
- `output/jesus_centric_kjv_all66.txt` — fully processed output
- `jesus_centric_kjv_processor.py` — the script that generated the output

Regenerate anytime:
```bash
python3 jesus_centric_kjv_processor.py input/kjv_gutenberg_10900.txt output/jesus_centric_kjv_all66.txt
```
