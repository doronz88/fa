from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def run(segments, args, addresses, **kwargs):
    print(addresses)
    return addresses
