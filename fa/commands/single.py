from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('single', description='reduces the result list into a singleton')
    return p


def run(segments, args, addresses, **kwargs):
    return [addresses.pop()] if len(addresses) >= 1 else []
