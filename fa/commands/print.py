from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('print',
                                   description='prints the current '
                                               'search results')
    return p


def run(segments, args, addresses, **kwargs):
    print(addresses)
    return addresses
