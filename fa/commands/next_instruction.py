from argparse import ArgumentParser, RawTextHelpFormatter
from typing import Iterable, List, Optional, Tuple
from fa import context, utils

try:
    import idautils
    import idc
except ImportError:
    pass

DESCRIPTION = '''Map the resultset to the next instruction of a given pattern. The instruction is searched for linearly.

Example #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}
    0x0000000c: mov r2, r3
    
    results = [0, 4, 8]
    -> next-instruction mov
    results = [0, 4, 12]

Example #2:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}
    0x0000000c: mov r2, r3
    
    results = [0, 4, 8]
    -> next-instruction mov --op 2
    results = [12, 12, 12]
'''


def get_parser() -> ArgumentParser:
    p = utils.ArgumentParserNoExit('next-instruction',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)

    p.add_argument('mnem', nargs='+')
    p.add_argument('--limit', type=int, help='Number of instructions to search per address', default=None)
    p.add_argument('--back', action='store_true', help='Search backwards instead of forwards')
    utils.add_operand_args(p)
    return p


def _find_next_instruction(mnems: Iterable[str],
                           regs_description: Iterable[Tuple[int, Iterable[str]]],
                           address: int,
                           backwards: bool = False,
                           limit: Optional[int] = None) -> Optional[int]:
    instructions = list(idautils.FuncItems(address))

    if backwards:
        instructions = [ea for ea in instructions if ea <= address][::-1]
    else:
        instructions = [ea for ea in instructions if ea >= address]

    if limit is not None:
        instructions = instructions[:limit]

    for ea in instructions:
        current_mnem = idc.print_insn_mnem(ea).lower()
        if current_mnem in mnems:
            if not regs_description:
                return ea

            for description in regs_description:
                index, values = description
                if not utils.compare_operand(ea, index, values):
                    break
            else:
                return ea

    return None


@context.ida_context
def next_instruction(addresses: List[int],
                     mnem: str,
                     regs_description: Iterable[Tuple[int, Iterable[str]]],
                     backwards: bool = False,
                     limit: Optional[int] = None) -> List[int]:
    for address in addresses:
        r = _find_next_instruction(mnem, regs_description, address, backwards, limit)
        if r is not None:
            yield r


def run(segments, args, addresses: List[int], interpreter=None, **kwargs):
    regs_description = utils.create_regs_description_from_args(args)
    return list(next_instruction(addresses, args.mnem, regs_description, args.back, args.limit))
