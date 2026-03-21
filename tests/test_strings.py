"""Tests for strings.py: string extraction, classification, and scoring."""

from pathlib import Path

from psp_etl.strings import (
    CATEGORIES,
    MIN_STRING_LENGTH,
    STRING_PATTERN,
    WEIGHTS,
    BlobAnalysis,
    analyze_blob,
    classify_string,
)


# ---------------------------------------------------------------------------
# STRING_PATTERN
# ---------------------------------------------------------------------------


def test_string_pattern_matches_printable_ascii():
    data = b"hello world"
    matches = [m.group() for m in STRING_PATTERN.finditer(data)]
    assert b"hello world" in matches


def test_string_pattern_minimum_length():
    # Exactly MIN_STRING_LENGTH chars — must match
    s = b"a" * MIN_STRING_LENGTH
    assert STRING_PATTERN.search(s) is not None


def test_string_pattern_too_short():
    s = b"a" * (MIN_STRING_LENGTH - 1)
    assert STRING_PATTERN.search(s) is None


def test_string_pattern_skips_non_printable():
    data = b"\x00\x01\x02hello\x00"
    matches = [m.group() for m in STRING_PATTERN.finditer(data)]
    assert b"hello" not in matches  # too short (5 bytes < 6)


def test_string_pattern_skips_non_printable_long():
    data = b"\x00\x01PSPInit\x00"
    matches = [m.group() for m in STRING_PATTERN.finditer(data)]
    assert b"PSPInit" in matches


# ---------------------------------------------------------------------------
# classify_string
# ---------------------------------------------------------------------------


def test_classify_format_string():
    assert classify_string("value=%d bytes") == "format_string"
    assert classify_string("addr=0x%08x") == "format_string"
    assert classify_string("msg=%s") == "format_string"


def test_classify_function_name_parens():
    assert classify_string("spiRead()") == "function_name"
    assert classify_string("BiosInit()") == "function_name"


def test_classify_function_name_amd_prefix():
    assert classify_string("AMD_SPI_INIT:") == "function_name"


def test_classify_error_message_upper():
    assert classify_string("ERROR: invalid state") == "error_message"
    assert classify_string("FAIL: checksum mismatch") == "error_message"
    assert classify_string("INVALID parameter") == "error_message"
    assert classify_string("ERR_NOT_SUPPORTED") == "error_message"


def test_classify_error_message_case_insensitive():
    assert classify_string("error: bad value") == "error_message"
    assert classify_string("fail: something went wrong here") == "error_message"


def test_classify_postcode_pspstatus():
    assert classify_string("PSPSTATUS_SUCCESS") == "postcode"


def test_classify_postcode_ablstatus():
    # "ABLSTATUS_FAIL_MEMORY" would match error_message first (FAIL); use a string
    # that only matches the postcode pattern
    assert classify_string("ABLSTATUS_SUCCESS") == "postcode"


def test_classify_descriptive_long():
    # >20 chars, no category match
    s = "This is a long description string"
    assert classify_string(s) == "descriptive"


def test_classify_other_short():
    # ≤20 chars, no category match
    assert classify_string("short text") == "other"


def test_classify_priority_format_over_error():
    # format_string is checked first and should win over error_message
    s = "ERROR: %d bytes"
    assert classify_string(s) == "format_string"


# ---------------------------------------------------------------------------
# CATEGORIES / WEIGHTS constants
# ---------------------------------------------------------------------------


def test_categories_keys():
    assert set(CATEGORIES) == {"format_string", "function_name", "error_message", "postcode"}


def test_weights_keys():
    assert set(WEIGHTS) >= {"format_string", "function_name", "error_message", "postcode", "descriptive", "other"}


def test_weights_values():
    assert WEIGHTS["format_string"] == 3
    assert WEIGHTS["function_name"] == 2
    assert WEIGHTS["error_message"] == 2
    assert WEIGHTS["postcode"] == 1
    assert WEIGHTS["descriptive"] == 0.5
    assert WEIGHTS["other"] == 0.1


# ---------------------------------------------------------------------------
# analyze_blob
# ---------------------------------------------------------------------------


def _write_blob(tmp_path: Path, content: bytes) -> Path:
    p = tmp_path / "test.bin"
    p.write_bytes(content)
    return p


def test_analyze_blob_empty(tmp_path):
    p = _write_blob(tmp_path, b"")
    result = analyze_blob(p)
    assert isinstance(result, BlobAnalysis)
    assert result.total_strings == 0
    assert result.unique_strings == 0
    assert result.score == 0.0
    assert result.strings == []


def test_analyze_blob_no_printable(tmp_path):
    p = _write_blob(tmp_path, b"\x00\x01\x02\x03\x04")
    result = analyze_blob(p)
    assert result.total_strings == 0


def test_analyze_blob_counts_raw_duplicates(tmp_path):
    # Same string appearing twice in the blob
    blob = b"\x00" + b"spiRead()" + b"\x00" + b"spiRead()" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.total_strings == 2
    assert result.unique_strings == 1


def test_analyze_blob_format_string(tmp_path):
    blob = b"\x00" + b"value=%d bytes ok" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.format_strings == 1
    assert result.score == WEIGHTS["format_string"]


def test_analyze_blob_function_name(tmp_path):
    blob = b"\x00" + b"spiRead()" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.function_names == 1
    assert result.score == WEIGHTS["function_name"]


def test_analyze_blob_error_message(tmp_path):
    blob = b"\x00" + b"ERROR: bad state" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.error_messages == 1
    assert result.score == WEIGHTS["error_message"]


def test_analyze_blob_postcode(tmp_path):
    blob = b"\x00" + b"PSPSTATUS_SUCCESS" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.postcode_strings == 1
    assert result.score == WEIGHTS["postcode"]


def test_analyze_blob_strings_list_contains_categories(tmp_path):
    blob = b"\x00" + b"spiRead()" + b"\x00" + b"ERROR: bad state" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    cats = {text: cat for text, cat in result.strings}
    assert cats.get("spiRead()") == "function_name"
    assert cats.get("ERROR: bad state") == "error_message"


def test_analyze_blob_descriptive(tmp_path):
    # Long string with no pattern match
    blob = b"\x00" + b"Initializing memory subsystem" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.descriptive_strings == 1


def test_analyze_blob_mixed_score(tmp_path):
    # 1 format_string (weight 3), 1 function_name (weight 2) → score = 5
    blob = b"\x00" + b"value=%d bytes ok" + b"\x00" + b"spiRead()" + b"\x00"
    p = _write_blob(tmp_path, blob)
    result = analyze_blob(p)
    assert result.format_strings == 1
    assert result.function_names == 1
    assert result.score == WEIGHTS["format_string"] + WEIGHTS["function_name"]


def test_analyze_blob_returns_blobbanalysis_instance(tmp_path):
    p = _write_blob(tmp_path, b"hello world!!")
    result = analyze_blob(p)
    assert isinstance(result, BlobAnalysis)
