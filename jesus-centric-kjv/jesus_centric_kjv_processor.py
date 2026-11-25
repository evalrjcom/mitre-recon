#!/usr/bin/env python3
"""
jesus_centric_kjv_processor_v001.py

Processes a public-domain KJV plain-text file into a Jesus-centric version:
- Independent modernization of archaic language (not derived from any copyrighted translation)
- LORD and GOD rendered in ALL CAPS
- Appends [JESUS] after configured divine/Jesus references

Usage:
    python3 jesus_centric_kjv_processor_v001.py input_kjv.txt output.txt

Expects a simple verse-per-line or plain KJV text. Robust single-pass processing.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Pattern, Tuple

# ---------------------------------------------------------------------------
# Modernization rules (independent of any copyrighted text)
# Applied in order; longer / more specific patterns first
# ---------------------------------------------------------------------------
MODERNIZATION_RULES: List[Tuple[Pattern, str]] = [
    (re.compile(r"\bthee\b", re.I), "you"),
    (re.compile(r"\bthou\b", re.I), "you"),
    (re.compile(r"\bthy\b", re.I), "your"),
    (re.compile(r"\bthine\b", re.I), "yours"),
    (re.compile(r"\bye\b", re.I), "you"),
    (re.compile(r"\bhath\b", re.I), "has"),
    (re.compile(r"\bdoth\b", re.I), "does"),
    (re.compile(r"\bsaith\b", re.I), "says"),
    (re.compile(r"\bbelieveth\b", re.I), "believes"),
    (re.compile(r"\bmaketh\b", re.I), "makes"),
    (re.compile(r"\bleadeth\b", re.I), "leads"),
    (re.compile(r"\brestoreth\b", re.I), "restores"),
    (re.compile(r"\bgoeth\b", re.I), "goes"),
    (re.compile(r"\bcometh\b", re.I), "comes"),
    (re.compile(r"\bsuffer\b", re.I), "let"),          # "suffer little children" sense
    (re.compile(r"\bconversation\b", re.I), "conduct"),
    (re.compile(r"\bprevent\b", re.I), "precede"),
    (re.compile(r"\bcharity\b", re.I), "love"),
    (re.compile(r"\bverily\b", re.I), "truly"),
    (re.compile(r"\bwhosoever\b", re.I), "whoever"),
    (re.compile(r"\bwhoso\b", re.I), "whoever"),
]

# Divine name capitalization
LORD_GOD_PATTERN = re.compile(r"\b(Lord|LORD|God|GOD)\b")

# Terms that should receive [JESUS] marker when they refer to Jesus.
# This is a practical starting set; perfect OT detection is theological and
# should be curated via the CONFIG section below.
JESUS_MARKER_TERMS = [
    # Core pronouns and divine names
    r"\b[Hh]e\b",
    r"\b[Hh]im\b",
    r"\b[Hh]is\b",
    r"\bLORD\b",
    r"\bGOD\b",
    # Explicit titles
    r"\bSon of Man\b",
    r"\bSon of God\b",
    r"\bChrist\b",
    r"\bJesus\b",
    r"\bMessiah\b",
    r"\bWord\b",
    # Evangelical Messianic / Christological titles
    r"\bLamb\b",
    r"\bSon\b",
    r"\bBranch\b",
    r"\bServant\b",
    r"\bShepherd\b",
    r"\bSeed\b",              # Gen 3:15, Gal 3:16
    r"\bShiloh\b",            # Gen 49:10
    r"\bStar\b",              # Num 24:17 (context-sensitive; used carefully)
    r"\bProphet\b",           # Deut 18:15 the Prophet like Moses
    r"\bImmanuel\b",
    r"\bWonderful\b",         # Isa 9:6
    r"\bCounsellor\b",
    r"\bPrince of Peace\b",
    r"\bRoot\b",              # Isa 11, Rev 5
    r"\bOffspring\b",
    r"\bKing\b",              # when in Messianic context; applied in target books
]

# All 66 books — markers now apply everywhere
TARGET_BOOKS = {
    # Old Testament
    "Genesis", "Exodus", "Leviticus", "Numbers", "Deuteronomy",
    "Joshua", "Judges", "Ruth", "1 Samuel", "2 Samuel",
    "1 Kings", "2 Kings", "1 Chronicles", "2 Chronicles",
    "Ezra", "Nehemiah", "Esther", "Job", "Psalms", "Proverbs",
    "Ecclesiastes", "Song of Solomon", "Isaiah", "Jeremiah",
    "Lamentations", "Ezekiel", "Daniel", "Hosea", "Joel",
    "Amos", "Obadiah", "Jonah", "Micah", "Nahum",
    "Habakkuk", "Zephaniah", "Haggai", "Zechariah", "Malachi",
    # New Testament
    "Matthew", "Mark", "Luke", "John", "Acts",
    "Romans", "1 Corinthians", "2 Corinthians", "Galatians",
    "Ephesians", "Philippians", "Colossians", "1 Thessalonians",
    "2 Thessalonians", "1 Timothy", "2 Timothy", "Titus",
    "Philemon", "Hebrews", "James", "1 Peter", "2 Peter",
    "1 John", "2 John", "3 John", "Jude", "Revelation",
}


def modernize_line(line: str) -> str:
    """Apply independent lexical modernizations."""
    for pattern, replacement in MODERNIZATION_RULES:
        line = pattern.sub(replacement, line)
    return line


def capitalize_divine(line: str) -> str:
    """Force LORD and GOD to all caps."""
    def repl(match: re.Match) -> str:
        word = match.group(0)
        if word.lower() in ("lord", "god"):
            return word.upper()
        return word
    return LORD_GOD_PATTERN.sub(repl, line)


def uppercase_jesus(line: str) -> str:
    """Force the name Jesus to uppercase everywhere."""
    return re.sub(r"\b[Jj]esus\b", "JESUS", line)


def add_jesus_marker(line: str, book: str) -> str:
    """Append [JESUS] after configured terms (all 66 books).
    The name JESUS itself is already uppercased and is not given a redundant marker.
    Other matched terms are uppercased and marked.
    """
    # Markers now apply across the entire Bible
    def repl(m: re.Match) -> str:
        text = m.group(0).upper()
        # Avoid JESUS[JESUS] redundancy
        if text == "JESUS":
            return text
        return f"{text}[JESUS]"

    for term in JESUS_MARKER_TERMS:
        pattern = re.compile(term, re.IGNORECASE)
        line = pattern.sub(repl, line)
    return line


def detect_book(line: str) -> str:
    """Book detector supporting common KJV plain-text formats.
    Handles:
    - 'Genesis 1:1 In the beginning...'
    - Gutenberg style 'Book 43     John'
    - Simple book headers
    """
    # Gutenberg book header: "Book 43     John" or "Book 01     Genesis"
    m = re.match(r"^Book\s+\d+\s+([1-3]?\s*[A-Za-z]+)", line.strip())
    if m:
        return m.group(1).strip()

    # Verse line with book name: "Genesis 1:1 ..."
    m = re.match(r"^([1-3]?\s*[A-Za-z]+)\s+\d+:", line)
    if m:
        return m.group(1).strip()

    # Fallback for header-style lines
    for book in TARGET_BOOKS:
        if line.startswith(book + " ") or line.strip() == book:
            return book
    return ""


def process_file(input_path: Path, output_path: Path) -> None:
    """Single-pass streaming processor. Safe for full Bible size."""
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    # Resolve paths and reject traversal
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if ".." in str(output_path):
        raise ValueError("Output path contains traversal segments")

    current_book = ""
    with input_path.open("r", encoding="utf-8", errors="replace") as fin, \
         output_path.open("w", encoding="utf-8") as fout:

        for raw_line in fin:
            line = raw_line.rstrip("\n")
            if not line.strip():
                fout.write("\n")
                continue

            # Update book context
            detected = detect_book(line)
            if detected:
                current_book = detected

            # Pipeline
            line = modernize_line(line)
            line = capitalize_divine(line)
            line = uppercase_jesus(line)          # always uppercase the name
            line = add_jesus_marker(line, current_book)

            fout.write(line + "\n")

    print(f"Processed: {input_path} -> {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a Jesus-centric modernized KJV with [JESUS] markers."
    )
    parser.add_argument("input", type=Path, help="Public-domain KJV plain text file")
    parser.add_argument("output", type=Path, help="Output file path")
    args = parser.parse_args()

    try:
        process_file(args.input, args.output)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
