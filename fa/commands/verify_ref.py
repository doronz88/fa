from fa.commands.locate import locate
from fa import utils, context

try:
    import idautils
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('verify-ref',
                                   description='verifies a given reference '
                                               'exists to current result set')
    p.add_argument('--code', action='store_true',
                   default=False, help='include code references')
    p.add_argument('--data', action='store_true',
                   default=False, help='include data references')
    p.add_argument('--name', default=None, help='symbol name')
    return p


@context.ida_context
def verify_ref(addresses, name=None, code=False, data=False):
    if name is not None:
        symbol = locate(name)

        if symbol == idc.BADADDR:
            return

    for address in addresses:
        refs = []
        if code:
            refs += list(idautils.CodeRefsFrom(address, 1))
        if data:
            refs += list(idautils.DataRefsFrom(address))

        if len(refs) == 0:
            continue

        for ref in refs:
            if name is not None:
                if address + 4 != ref and symbol == ref:
                    yield address
                    break
            else:
                if address + 4 != ref:
                    yield address
                    break


@utils.yield_unique
def verify_ref_unique(addresses, name, code=False, data=False):
    for address in verify_ref(addresses, name, code=code, data=data):
        yield address


@context.ida_context
def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(set(verify_ref(addresses, args.name,
                               code=args.code, data=args.data)))
