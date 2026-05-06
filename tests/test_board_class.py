"""Tests for the socket → board_class classifier."""

import pytest

from psp_etl.ingest import BOARD_CLASSES, classify_board_class


@pytest.mark.parametrize(
    "socket,expected",
    [
        ("AM4", "Ryzen"),
        ("AM5", "Ryzen"),
        ("SP3", "EPYC"),
        ("SP5", "EPYC"),
        ("SP6", "EPYC"),
        ("sTRX4", "Threadripper"),
        ("sTR5", "Threadripper"),
        ("sWRX8", "ThreadripperPro"),
    ],
)
def test_known_socket_maps_to_canonical_board_class(socket, expected):
    assert classify_board_class(socket) == expected


def test_none_socket_returns_none():
    assert classify_board_class(None) is None


@pytest.mark.parametrize("socket", ["", "FM2", "LGA1700", "am4", "AM-4"])
def test_unknown_socket_returns_none(socket):
    """Mapping is case-sensitive and exact-match — anything else is NULL."""
    assert classify_board_class(socket) is None


def test_all_mapped_classes_are_in_BOARD_CLASSES():
    """Every value the classifier can return must appear in the public enum."""
    sockets = ["AM4", "AM5", "SP3", "SP5", "SP6", "sTRX4", "sTR5", "sWRX8"]
    produced = {classify_board_class(s) for s in sockets}
    assert produced <= set(BOARD_CLASSES)


def test_embedded_is_reserved_but_unmapped():
    """'Embedded' is a valid board_class value but no socket maps to it yet."""
    assert "Embedded" in BOARD_CLASSES
    sockets = ["AM4", "AM5", "SP3", "SP5", "SP6", "sTRX4", "sTR5", "sWRX8"]
    assert "Embedded" not in {classify_board_class(s) for s in sockets}
