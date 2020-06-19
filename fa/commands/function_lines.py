from fa import utils, context

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('function-lines',
                                   description='get all function lines')
    return p


@context.ida_context
@utils.yield_unique
def function_lines(addresses):
    for address in addresses:
        for item in idautils.FuncItems(address):
            yield item


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(function_lines(addresses))
