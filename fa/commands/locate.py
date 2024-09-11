from argparse import RawTextHelpFormatter
from typing import Iterable, List

from fa import context, utils

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''goto symbol by name

EXAMPLE:
    0x00000000: main:
    0x00000000:     mov r0, r1
    0x00000004: foo:
    0x00000004:     bx lr

    results = [0, 4]
    -> locate foo
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('locate',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name', nargs='+')
    return p


@context.ida_context
def locate_single(name) -> int:
    return idc.get_name_ea_simple(name)


def locate(names: Iterable[str]) -> List[int]:
    result = []
    for n in names:
        located = locate_single(n)
        if located != idc.BADADDR:
            result.append(located)
    return result


def run(segments, args, addresses: Iterable[int], interpreter=None, **kwargs) -> List[int]:
    return locate(args.name)
