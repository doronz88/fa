from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('unique',
                                   description='verifies the result-list '
                                               'contains a single value')
    return p


def run(segments, args, addresses, **kwargs):
    return addresses if len(addresses) == 1 else []
