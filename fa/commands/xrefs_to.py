from fa.commands import utils

IDA_MODULE = False

try:
    import idc
    import idaapi
    import _idaapi
    import idautils

    IDA_MODULE = True
except ImportError:
    pass


def run(segments, manner, manner_args, addresses, args, **kwargs):
    utils.verify_ida()

    occurences = utils.ida_find_all(args)

    functions = set()
    for ea in occurences:
        for ref in idautils.XrefsTo(ea):
            functions.add(idc.GetFunctionAttr(ref.frm, idc.FUNCATTR_START))

    functions = list(functions)

    retval = set()
    retval.update(addresses)

    if manner == 'or':
        retval.update(functions)

    elif manner == 'and':
        addresses_functions = set([idc.GetFunctionAttr(ea, idc.FUNCATTR_START) for ea in addresses])
        retval.intersection_update(addresses_functions)

    return retval
