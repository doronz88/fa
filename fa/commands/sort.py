from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def run(segments, args, addresses, **kwargs):
    addresses = list(addresses)
    addresses.sort()
    return addresses
