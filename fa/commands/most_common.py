import idautils

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def most_common(addresses):
    addresses = list(addresses)
    if len(addresses) == 0:
        return []
    return [max(set(addresses), key=addresses.count)]


def run(segments, args, addresses, **kwargs):
    return most_common(addresses)
