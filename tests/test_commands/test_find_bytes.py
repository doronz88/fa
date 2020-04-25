from collections import OrderedDict

import pytest

from tests.utils.mock_fa import MockFaInterp


@pytest.mark.parametrize("segments,instruction,result", [
    # Sanity
    ([(0x12345678, "\x11\x22\x33\x44")], "find-bytes --or '11223344'",
     [0x12345678]),
    ([(0x12345678, "\x00\x00\x00\x00")], "find-bytes --or '00000000'",
     [0x12345678]),
    ([(0x12345678, "\xff\xff\xff\xff")], "find-bytes --or 'ffffffff'",
     [0x12345678]),
    # No results
    ([(0x12345678, "\x11\x22\x33\x45")], "find-bytes --or '11223344'", []),
    ([(0x12345678, "\x00\x00\x00\x00")], "find-bytes --or '11223344'", []),
    ([(0x12345678, "\xff\xff\xff\xff")], "find-bytes --or '11223344'", []),
    ([(0x12345678, "\x44\x33\x22\x11")], "find-bytes --or '11223344'", []),
    # Multiple results in the same segment
    ([(0x12345678, "\x11\x22\x33\x44\x00\x00\x00\x00\x11\x22\x33\x44")],
     "find-bytes --or '11223344'", [0x12345678, 0x12345680]),
    # Multiple results in the different segments
    ([(0x12345678, "\x11\x22\x33\x44"), (0x55554444, "\x11\x22\x33\x44")],
     "find-bytes --or '11223344'", [0x12345678, 0x55554444]),
    # Multiple results
    ([(0x12345678, "\x11\x22\x33\x44\x00\x00\x00\x00\x11\x22\x33\x44"),
      (0x55554444, "\x11\x22\x33\x44")],
     "find-bytes --or '11223344'", [0x12345678, 0x12345680, 0x55554444]),
    # Overlapping results in the same segment
    ([(0x12345678, "\x11\x22\x11\x22\x11\x22")], "find-bytes --or '11221122'",
     [0x12345678, 0x1234567a]),
    # Overlapping results in different segments - not supported!
    ([(0x12345678, "\x11\x22\x11\x22"), (0x1234567c, "\x11\x22\x33\x44")],
     "find-bytes --or '11221122'", [0x12345678]),
])
def test_find_bytes_or(segments, instruction, result):
    analyzer = MockFaInterp()
    analyzer.segments = OrderedDict(segments)
    assert analyzer.find_from_instructions_list([instruction]) == result


@pytest.mark.parametrize("segments,instructions,result", [
    # Sanity
    ([(0x12345678, "\x11\x22\x33\x44\x11\x22\x11\x22")],
     ["find-bytes --or '11223344'", "find-bytes --or '11221122'"],
     [0x12345678, 0x1234567c]),
    # Results across segments
    ([(0x12345678, "\x11\x22\x33\x44"), (0x55554444, "\x11\x22\x11\x22")],
     ["find-bytes --or '11223344'", "find-bytes --or '11221122'"],
     [0x12345678, 0x55554444]),
    # First find has no results
    ([(0x12345678, "\x11\x22\x33\x45\x11\x22\x11\x22")],
     ["find-bytes --or '11223344'", "find-bytes --or '11221122'"],
     [0x1234567c]),
    # Second find has no results
    ([(0x12345678, "\x11\x22\x33\x44\x11\x22\x11\x23")],
     ["find-bytes --or '11223344'", "find-bytes --or '11221122'"],
     [0x12345678]),
    # Same address across finds
    ([(0x12345678, "\x11\x22\x33\x44\x11\x22\x11\x23")],
     ["find-bytes --or '11223344'", "find-bytes --or '11223344'"],
     [0x12345678]),
])
def test_multiple_find_bytes_or(segments, instructions, result):
    analyzer = MockFaInterp()
    analyzer.segments = OrderedDict(segments)
    assert analyzer.find_from_instructions_list(instructions) == result


@pytest.mark.parametrize("instruction", [
    "find-bytes --and '11223344'"
])
def test_find_bytes_with_wrong_manner(instruction):
    analyzer = MockFaInterp()
    with pytest.raises(ValueError):
        assert analyzer.find_from_instructions_list([instruction])
