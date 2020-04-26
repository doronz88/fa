from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def run(segments, args, addresses, **kwargs):
    return addresses if len(addresses) == 1 else []
