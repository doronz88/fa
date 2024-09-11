from typing import List

from fa.commands.locate import locate_single
from fa.fa_types import IDA_MODULE
from fa.utils import ArgumentParserNoExit

try:
    import ida_bytes
    import ida_name
    from ida_idaapi import BADADDR
except ImportError:
    pass


def get_parser() -> ArgumentParserNoExit:
    p = ArgumentParserNoExit('set-name',
                             description='set symbol name')
    p.add_argument('name')
    return p


def is_address_nameless(addr: int) -> bool:
    return not ida_bytes.f_has_user_name(ida_bytes.get_flags(addr), None)


def set_name(addresses: List[int], name: str, interpreter) -> List[int]:
    for ea in addresses:
        if IDA_MODULE:
            current_name = ida_name.get_ea_name(ea)
            remote_addr = locate_single(current_name)
            if current_name == name:
                continue

            # we want to avoid accidental renames from bad sigs, therefore we assert the following:
            assert remote_addr == BADADDR, f'Rename failed, name already used at {hex(remote_addr)} ({hex(ea)})'
            assert is_address_nameless(ea), f'Rename failed, address has a different name {current_name} ({hex(ea)})'

        interpreter.set_symbol(name, ea)
    return addresses


def run(segments, args, addresses: List[int], interpreter=None, **kwargs) -> List[int]:
    return set_name(addresses, args.name, interpreter)
