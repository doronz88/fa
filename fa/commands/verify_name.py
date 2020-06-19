from fa import utils, context
from fa.commands.locate import locate


def get_parser():
    p = utils.ArgumentParserNoExit('verify-name',
                                   description='verifies the given name '
                                               'appears in result set')
    p.add_argument('name')
    return p


@context.ida_context
@utils.yield_unique
def verify_name(addresses, name):
    ref = locate(name)
    for address in addresses:
        if ref == address:
            yield address


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(verify_name(addresses, args.name))
