from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('most-common',
                                   description='get the result appearing the '
                                               'most in the result-set')
    return p


def most_common(addresses):
    addresses = list(addresses)
    if len(addresses) == 0:
        return []
    return [max(set(addresses), key=addresses.count)]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return most_common(addresses)
