from argparse import RawTextHelpFormatter
from typing import Generator, List, Union

from fa import context, utils

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''reduce the result-set to those matching the given instruction

EXAMPLE #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-opcode mov
    results = [0, 4]

EXAMPLE #2:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [0, 2, 4, 6, 8]
    -> verify-opcode mov --op1 r2
    results = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('verify-opcode',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('mnem', nargs='+')
    utils.add_operand_args(p)
    return p


@context.ida_context
@utils.yield_unique
def verify_opcode(addresses: List[int], mnems: Union[str, List[str]], regs_description) \
        -> Generator[int, None, None]:
    for ea in addresses:
        current_mnem = idc.print_insn_mnem(ea).lower()
        if current_mnem in mnems:
            if not regs_description:
                yield ea
                continue

            for description in regs_description:
                index, values = description
                if not utils.compare_operand(ea, index, values):
                    break
            else:
                yield ea


def run(segments, args, addresses: List[int], interpreter=None, **kwargs) -> List[int]:
    regs_description = utils.create_regs_description_from_args(args)
    return list(verify_opcode(addresses, args.mnem, regs_description))
