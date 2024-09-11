import re
from argparse import ArgumentParser, RawTextHelpFormatter
from collections.abc import Iterable
from typing import Generator, List

try:
    import idc
except ImportError:
    pass

from fa import context, utils

DESCRIPTION = '''reduce the result-set to those in the given segment name

EXAMPLE:
    .text:0x00000000 01 02 03 04
    .text:0x00000004 30 31 32 33

    .data:0x00000200 01 02 03 04
    .data:0x00000204 30 31 32 33

    results = [0, 0x200]
    -> verify-segment .data
    results = [0x200]
'''


@context.ida_context
def verify_segment(addresses: Iterable[int], segment_name: str, is_regex: bool = False) -> Generator[int, None, None]:
    if is_regex:
        matcher = re.compile(segment_name)

        def match(n) -> bool:
            return bool(matcher.match(n))
    else:
        def match(n) -> bool:
            return segment_name == n

    for ea in addresses:
        real_seg_name = idc.get_segm_name(ea)
        if match(real_seg_name):
            yield ea


def get_parser() -> ArgumentParser:
    p = utils.ArgumentParserNoExit()
    p.add_argument('name', help='segment name')
    p.add_argument('--regex', help='interpret name as a regex', action='store_true')

    p.prog = 'verify-segment'
    p.description = DESCRIPTION
    p.formatter_class = RawTextHelpFormatter
    return p


def run(segments, args, addresses: Iterable[int], interpreter=None, **kwargs) -> List[int]:
    return list(verify_segment(addresses, args.name, args.regex))
