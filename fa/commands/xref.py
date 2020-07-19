from fa import utils, context

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('xref',
                                   description='goto xrefs pointing at'
                                               ' current search results')
    return p


@context.ida_context
def xref(addresses):
    for address in addresses:
        for ref in idautils.XrefsTo(address):
            yield ref.frm


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(xref(addresses))
