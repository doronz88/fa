from fa.commands import utils
from fa.commands import function_start
reload(function_start)
reload(utils)

try:
    import idc
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit(prog='xrefs-to')
    p.add_argument('--function-start', action='store_true')
    p.add_argument('--or', action='store_true')
    p.add_argument('--and', action='store_true')
    p.add_argument('--name')
    p.add_argument('--bytes')
    return p


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    if args.name:
        ea = idc.LocByName(args.name)
        occurrences = [ea] if ea != idc.BADADDR else []
    else:
        occurrences = utils.ida_find_all(args.bytes)

    frm = set()
    for ea in occurrences:
        froms = [ref.frm for ref in idautils.XrefsTo(ea)]

        if args.function_start:
            froms = [function_start.get_function_start(segments, ea)
                     for ea in froms]

        frm.update(froms)

    retval = set()
    retval.update(addresses)

    if getattr(args, 'or'):
        retval.update(frm)

    elif getattr(args, 'and'):
        addresses_functions = set([idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
                                   for ea in addresses])
        retval.intersection_update(addresses_functions)

    return list(retval)
