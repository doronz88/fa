from fa.commands import utils
from fa.commands import function_start

try:
    import idc
    import idaapi
    import _idaapi
    import idautils
except ImportError:
    pass


def run(segments, manners, addresses, args, **kwargs):
    utils.verify_ida()

    occurences = utils.ida_find_all(str(args))

    frm = set()
    for ea in occurences:
        froms = [ref.frm for ref in idautils.XrefsTo(ea)]

        if 'function-start' in manners:
            froms = [function_start.get_function_start(segments, ea) for ea in froms]

        frm.update(froms)

    retval = set()
    retval.update(addresses)

    if 'or' in manners.keys():
        retval.update(frm)

    elif 'and' in manners.keys():
        addresses_functions = set([idc.GetFunctionAttr(ea, idc.FUNCATTR_START) for ea in addresses])
        retval.intersection_update(addresses_functions)

    return list(retval)
