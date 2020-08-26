from fa import utils, context
from fa.commands import function_start

try:
    import idc
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit(prog='xrefs-to',
                                   description='search for xrefs pointing '
                                               'at given parameter')
    p.add_argument('--function-start', action='store_true',
                   help='goto function prolog for each xref')
    p.add_argument('--or', action='store_true',
                   help='expand the current result set')
    p.add_argument('--and', action='store_true',
                   help='reduce the current result set')
    p.add_argument('--name', help='parameter as label name')
    p.add_argument('--bytes', help='parameter as bytes')
    return p


@context.ida_context
def run(segments, args, addresses, interpreter=None, **kwargs):
    if args.name:
        ea = idc.LocByName(args.name)
        occurrences = [ea] if ea != idc.BADADDR else []
    else:
        occurrences = list(utils.ida_find_all(args.bytes))

    frm = set()
    for ea in occurrences:
        froms = [ref.frm for ref in idautils.XrefsTo(ea)]

        if args.function_start:
            froms = [function_start.get_function_start(segments, ea)
                     for ea in froms]

        frm.update(frm for frm in froms if frm != idc.BADADDR)

    retval = set()
    retval.update(addresses)

    if getattr(args, 'or'):
        retval.update(frm)

    elif getattr(args, 'and'):
        retval.intersection_update(frm)

    return list(retval)
