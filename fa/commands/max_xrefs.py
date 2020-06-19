from fa import utils, context

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('max-xrefs',
                                   description='get the result with'
                                               ' most xrefs pointing '
                                               'at it')
    return p


@context.ida_context
def max_xrefs(addresses):
    xrefs = []
    for address in addresses:
        xrefs.append((address, len([ref.frm for ref in
                                    idautils.XrefsTo(address)])))

    if len(xrefs) > 0:
        address, _ = max(xrefs, key=lambda x: x[1])
        return [address]

    return []


def run(segments, args, addresses, interpreter=None, **kwargs):
    return max_xrefs(addresses)
