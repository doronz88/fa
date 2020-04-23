from collections import OrderedDict

import pytest

from tests.utils.mock_fa import MockFa


@pytest.mark.parametrize("segments,instruction,result", [
    # Sanity
    ([(0x12345678, "\x11\x22\x33\x44")], "find-bytes/or 11223344",
     [0x12345678]),
    # No results
    ([(0x12345678, "\x11\x22\x33\x45")], "find-bytes/or 11223344", []),
    # Multiple results in the same segment
    ([(0x12345678, "\x11\x22\x33\x44\x00\x00\x00\x00\x11\x22\x33\x44")],
     "find-bytes/or 11223344", [0x12345678, 0x12345680]),
    # Multiple results in the different segments
    ([(0x12345678, "\x11\x22\x33\x44"), (0x55554444, "\x11\x22\x33\x44")],
     "find-bytes/or 11223344", [0x12345678, 0x55554444]),
])
def test_find_bytes_or(segments, instruction, result):
    analyzer = MockFa()
    analyzer.segments = OrderedDict(segments)
    assert analyzer.find_from_instructions_list([instruction]) == result
