from collections import OrderedDict

from tests.utils.mock_fa import MockFa


def test_find_bytes_or_sanity():
    analyzer = MockFa()
    address = 0x12345678
    analyzer.segments = OrderedDict([(address, "\x11\x22\x33\x44")])
    instructions = ["find-bytes/or 11223344"]
    assert analyzer.find_from_instructions_list(instructions) == [address]
