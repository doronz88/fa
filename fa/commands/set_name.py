from typing import List

from fa.utils import ArgumentParserNoExit

try:
    import ida_bytes
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
        interpreter.set_symbol(name, ea)
    return addresses


def run(segments, args, addresses: List[int], interpreter=None, **kwargs) -> List[int]:
    return set_name(addresses, args.name, interpreter)
