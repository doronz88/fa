from fa.commands import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('goto-ref', description='goto reference')
    p.add_argument('--code', action='store_true', default=False, help='include code references')
    p.add_argument('--data', action='store_true', default=False, help='include data references')
    return p


def goto_ref(addresses, code=False, data=False):
    for address in addresses:
        refs = []
        if code:
            refs += list(idautils.CodeRefsFrom(address, 1))
        if data:
            refs += list(idautils.DataRefsFrom(address))

        if len(refs) == 0:
            continue

        for ref in refs:
            if address + 4 != ref:
                yield ref


@utils.yield_unique
def goto_ref_unique(addresses, code=False, data=False):
    for address in goto_ref(addresses, code=code, data=data):
        yield address


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    return list(set(goto_ref(addresses, code=args.code, data=args.data)))
