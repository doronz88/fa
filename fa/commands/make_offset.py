from fa import context, utils

try:
    import ida_auto
    import ida_offset
    import idaapi
    from idc import REF_OFF8, REF_OFF16, REF_OFF32, REF_OFF64
except ImportError:
    pass


DESCRIPTION = '''convert into an offset

EXAMPLE:
    0x00000200: 01 02 03 04
    0x00000204: 00 02 00 00

    results = [0x204]
    -> make-offset
    results = [0x204]

    0x00000200: 01 02 03 04
    0x00000204: byte_200
'''


def get_parser():
    p = utils.ArgumentParserNoExit('make-offset',
                                   description=DESCRIPTION)
    p.add_argument('-l', '--len', type=int, default=0, help='length of offset in bytes')
    return p


@context.ida_context
def make_offset(addresses: list[int], offset_len: int = 0):
    offset_length_to_ref_type = {
        0: REF_OFF64 if idaapi.get_inf_structure().is_64bit() else REF_OFF32,
        1: REF_OFF8,
        2: REF_OFF16,
        4: REF_OFF32,
        8: REF_OFF64,
    }
    for ea in addresses:
        ida_offset.op_offset(ea, 0, offset_length_to_ref_type[offset_len])

    ida_auto.auto_wait()

    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_offset(addresses, args.len)
