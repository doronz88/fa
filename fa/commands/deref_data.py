from typing import List

from fa import context, utils

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''Dereference pointer as integer data type.

Note that the data is assumed to be stored in little endian format.

Example #1:
    0x00000000: LDR R1, [SP, #0x34]
    
    results = [0]
    -> deref-data -l 4
    results = [0xe5d1034]

Example #2:
    0x00000000: LDR R1, [SP, #0x34]
    
    results = [0]
    -> deref-data -l 2
    results = [0x1034]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('deref-data',
                                   description=DESCRIPTION)
    p.add_argument('-l', '--len', type=int, required=True,
                   help='length of the data in bytes')
    return p


@context.ida_context
def deref_data(addresses: List[int], data_len: int) -> List[int]:
    return [int.from_bytes(idc.get_bytes(ea, data_len), 'little') for ea in addresses]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return deref_data(addresses, args.len)
