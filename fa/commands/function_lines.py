from fa import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('function-lines',
                                   description='get all function lines')
    return p


@utils.yield_unique
def function_lines(addresses):
    for address in addresses:
        for item in idautils.FuncItems(address):
            yield item


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    return list(function_lines(addresses))
