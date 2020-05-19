from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('sort', description='performs a python-sort on the current result list')
    return p


def run(segments, args, addresses, **kwargs):
    addresses = list(addresses)
    addresses.sort()
    return addresses
