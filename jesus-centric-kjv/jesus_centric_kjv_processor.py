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
import json
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
    (re.compile(r"\bsuffer\b", re.I), "let"),
    (re.compile(r"\bconversation\b", re.I), "conduct"),
    (re.compile(r"\bprevent\b", re.I), "precede"),
    (re.compile(r"\bcharity\b", re.I), "love"),
    (re.compile(r"\bverily\b", re.I), "truly"),
    (re.compile(r"\bwhosoever\b", re.I), "whoever"),
    (re.compile(r"\bwhoso\b", re.I), "whoever"),
]

# Divine name capitalization
LORD_GOD_PATTERN = re.compile(r"\b(Lord|LORD|God|GOD)\b")

# Optional lemma list (STEPBible / MorphGNT inspired)
LEMMA_FILE = Path(__file__).with_name("messianic_lemmas.json")

def load_lemmas() -> set:
    """Load english triggers from the small lemma list if present."""
    if not LEMMA_FILE.is_file():
        return set()
    try:
        data = json.loads(LEMMA_FILE.read_text(encoding="utf-8"))
        return set(data.get("english_triggers", []))
    except Exception:
        return set()

LEMMA_TRIGGERS = load_lemmas()

# High-confidence Messianic / Christophanic chapters (evangelical apologetics)
MESSIANIC_CHAPTERS = {
    "Genesis": [3, 49],
    "Exodus": [3, 23],
    "Numbers": [24],
    "Deuteronomy": [18],
    "Psalms": [2, 16, 22, 45, 72, 110, 118],
    "Isaiah": [7, 9, 11, 42, 49, 50, 52, 53],
    "Jeremiah": [23, 31],
    "Ezekiel": [34],
    "Daniel": [7, 9],
    "Micah": [5],
    "Zechariah": [3, 6, 9, 12, 13],
    "Malachi": [3],
}

NT_BOOKS = {
    "Matthew", "Mark", "Luke", "John", "Acts",
    "Romans", "1 Corinthians", "2 Corinthians", "Galatians",
    "Ephesians", "Philippians", "Colossians", "1 Thessalonians",
    "2 Thessalonians", "1 Timothy", "2 Timothy", "Titus",
    "Philemon", "Hebrews", "James", "1 Peter", "2 Peter",
    "1 John", "2 John", "3 John", "Jude", "Revelation",
}

EXPLICIT_TITLE_TERMS = [
    r"\bSon of Man\b",
    r"\bSon of God\b",
    r"\bChrist\b",
    r"\bMessiah\b",
    r"\bWord\b",
    r"\bLamb\b",
    r"\bImmanuel\b",
    r"\bPrince of Peace\b",
    r"\bWonderful\b",
    r"\bCounsellor\b",
]

AMBIGUOUS_TERMS = [
    r"\b[Hh]e\b",
    r"\b[Hh]im\b",
    r"\b[Hh]is\b",
    r"\bLORD\b",
    r"\bGOD\b",
    r"\bSon\b",
    r"\bBranch\b",
    r"\bServant\b",
    r"\bShepherd\b",
    r"\bSeed\b",
    r"\bKing\b",
]

TARGET_BOOKS = {
    "Genesis", "Exodus", "Leviticus", "Numbers", "Deuteronomy",
    "Joshua", "Judges", "Ruth", "1 Samuel", "2 Samuel",
    "1 Kings", "2 Kings", "1 Chronicles", "2 Chronicles",
    "Ezra", "Nehemiah", "Esther", "Job", "Psalms", "Proverbs",
    "Ecclesiastes", "Song of Solomon", "Isaiah", "Jeremiah",
    "Lamentations", "Ezekiel", "Daniel", "Hosea", "Joel",
    "Amos", "Obadiah", "Jonah", "Micah", "Nahum",
    "Habakkuk", "Zephaniah", "Haggai", "Zechariah", "Malachi",
    "Matthew", "Mark", "Luke", "John", "Acts",
    "Romans", "1 Corinthians", "2 Corinthians", "Galatians",
    "Ephesians", "Philippians", "Colossians", "1 Thessalonians",
    "2 Thessalonians", "1 Timothy", "2 Timothy", "Titus",
    "Philemon", "Hebrews", "James", "1 Peter", "2 Peter",
    "1 John", "2 John", "3 John", "Jude", "Revelation",
}

def modernize_line(line: str) -> str:
    for pattern, replacement in MODERNIZATION_RULES:
        line = pattern.sub(replacement, line)
    return line

def capitalize_divine(line: str) -> str:
    def repl(match: re.Match) -> str:
        word = match.group(0)
        if word.lower() in ("lord", "god"):
            return word.upper()
        return word
    return LORD_GOD_PATTERN.sub(repl, line)

def uppercase_jesus(line: str) -> str:
    return re.sub(r"\b[Jj]esus\b", "JESUS", line)

def add_jesus_marker(line: str, book: str, chapter: int, in_angel_scene: bool) -> str:
    def repl(m: re.Match) -> str:
        text = m.group(0).upper()
        if text == "JESUS":
            return text
        return f"{text}[JESUS]"

    all_explicit = EXPLICIT_TITLE_TERMS + [rf"\b{re.escape(t)}\b" for t in LEMMA_TRIGGERS]
    for term in all_explicit:
        pattern = re.compile(term, re.IGNORECASE)
        line = pattern.sub(repl, line)

    mark_ambiguous = False
    if book in NT_BOOKS:
        mark_ambiguous = True
    elif book in MESSIANIC_CHAPTERS and chapter in MESSIANIC_CHAPTERS.get(book, []):
        mark_ambiguous = True
    elif in_angel_scene:
        mark_ambiguous = True

    if mark_ambiguous:
        for term in AMBIGUOUS_TERMS:
            pattern = re.compile(term, re.IGNORECASE)
            line = pattern.sub(repl, line)

    return line

def detect_book(line: str) -> str:
    m = re.match(r"^Book\s+\d+\s+([1-3]?\s*[A-Za-z]+)", line.strip())
    if m:
        return m.group(1).strip()
    m = re.match(r"^([1-3]?\s*[A-Za-z]+)\s+\d+:", line)
    if m:
        return m.group(1).strip()
    for book in TARGET_BOOKS:
        if line.startswith(book + " ") or line.strip() == book:
            return book
    return ""

def process_file(input_path: Path, output_path: Path) -> None:
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    input_path = input_path.resolve()
    output_path = output_path.resolve()
    if ".." in str(output_path):
        raise ValueError("Output path contains traversal segments")

    current_book = ""
    current_chapter = 0
    in_angel_scene = False
    angel_scene_lines = 0

    with input_path.open("r", encoding="utf-8", errors="replace") as fin, \
         output_path.open("w", encoding="utf-8") as fout:

        for raw_line in fin:
            line = raw_line.rstrip("\n")
            if not line.strip():
                fout.write("\n")
                continue

            detected = detect_book(line)
            if detected:
                current_book = detected
                current_chapter = 0
                in_angel_scene = False

            m_chap = re.match(r"^(\d+):", line)
            if m_chap:
                current_chapter = int(m_chap.group(1))

            if re.search(r"angel of the LORD", line, re.I):
                in_angel_scene = True
                angel_scene_lines = 0
            if in_angel_scene:
                angel_scene_lines += 1
                if angel_scene_lines > 25:
                    in_angel_scene = False

            line = modernize_line(line)
            line = capitalize_divine(line)
            line = uppercase_jesus(line)
            line = add_jesus_marker(line, current_book, current_chapter, in_angel_scene)

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
