from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('unique',
                                   description='verifies the result-list '
                                               'contains a single value')
    return p


def unique(addresses):
    return addresses if len(addresses) == 1 else []


def run(segments, args, addresses, interpreter=None, **kwargs):
    return unique(addresses)
