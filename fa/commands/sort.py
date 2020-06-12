from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('sort',
                                   description='performs a python-sort on '
                                               'the current result list')
    return p


def sort(addresses):
    addresses.sort()
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return sort(addresses)
