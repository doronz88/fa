from fa import utils, context

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('min-xrefs',
                                   description='get the result with'
                                               ' least xrefs pointing '
                                               'at it')
    return p


@context.ida_context
def min_xrefs(addresses):
    xrefs = []
    for address in addresses:
        xrefs.append((address, len([ref.frm for ref in
                                    idautils.XrefsTo(address)])))

    if len(xrefs) > 0:
        address, _ = min(xrefs, key=lambda x: x[1])
        return [address]

    return []


def run(segments, args, addresses, interpreter=None, **kwargs):
    return min_xrefs(addresses)
