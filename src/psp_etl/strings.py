"""String extraction, classification, and scoring for PSP firmware blobs."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

MIN_STRING_LENGTH = 6

# Match printable ASCII runs of at least MIN_STRING_LENGTH characters
STRING_PATTERN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LENGTH)

CATEGORIES: dict[str, re.Pattern[str]] = {
    "format_string": re.compile(r"%[0-9]*[sdxXpuiolcfFeEgG]"),
    "function_name": re.compile(r"\w{3,}\(\)|AMD_\w+:"),
    "error_message": re.compile(r"(?:ERROR|FAIL|INVALID|ERR_)", re.I),
    "postcode": re.compile(r"(?:PSPSTATUS|ABLSTATUS)_\w+"),
}

WEIGHTS: dict[str, float] = {
    "format_string": 3,
    "function_name": 2,
    "error_message": 2,
    "postcode": 1,
    "descriptive": 0.5,
    "other": 0.1,
}


@dataclass
class BlobAnalysis:
    """Result of analyzing a firmware blob for debug strings."""

    total_strings: int
    unique_strings: int
    format_strings: int
    function_names: int
    error_messages: int
    postcode_strings: int
    descriptive_strings: int
    score: float
    strings: list[tuple[str, str]]  # (text, category) pairs for the strings table


def classify_string(s: str) -> str:
    """Return the category for a single extracted string."""
    for category, pattern in CATEGORIES.items():
        if pattern.search(s):
            return category
    if len(s) > 20:
        return "descriptive"
    return "other"


def analyze_blob(blob_path: Path) -> BlobAnalysis:
    """Extract, classify, and score all strings in a firmware blob.

    Reads raw bytes from *blob_path*, extracts printable ASCII runs, deduplicates
    them, classifies each unique string, and returns a :class:`BlobAnalysis` with
    aggregate counts and the per-string (text, category) pairs ready for DB insert.
    """
    data = blob_path.read_bytes()
    raw_strings = [m.group().decode("ascii") for m in STRING_PATTERN.finditer(data)]
    unique = list(set(raw_strings))

    classified = [(s, classify_string(s)) for s in unique]
    counts: Counter[str] = Counter(cat for _, cat in classified)
    score = sum(counts.get(cat, 0) * w for cat, w in WEIGHTS.items())

    return BlobAnalysis(
        total_strings=len(raw_strings),
        unique_strings=len(unique),
        format_strings=counts.get("format_string", 0),
        function_names=counts.get("function_name", 0),
        error_messages=counts.get("error_message", 0),
        postcode_strings=counts.get("postcode", 0),
        descriptive_strings=counts.get("descriptive", 0),
        score=score,
        strings=classified,
    )
