from fa.commands import utils

try:
    import idc
    import idaapi
    import _idaapi
    import idautils
except ImportError:
    pass


def run(segments, manner, manner_args, addresses, args, **kwargs):
    utils.verify_ida()

    occurences = utils.ida_find_all(args)

    frm = set()
    for ea in occurences:
        frm.update([ref.frm for ref in idautils.XrefsTo(ea)])

    retval = set()
    retval.update(addresses)

    if manner == 'or':
        retval.update(frm)

    elif manner == 'and':
        addresses_functions = set([idc.GetFunctionAttr(ea, idc.FUNCATTR_START) for ea in addresses])
        retval.intersection_update(addresses_functions)

    return retval
