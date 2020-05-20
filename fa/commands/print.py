from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('print',
                                   description='prints the current '
                                               'search results')
    return p


def run(segments, args, addresses, **kwargs):
    log_line = 'FA Debug Print: '
    for ea in addresses:
        log_line += '0x{:x} '.format(ea)
    print(log_line)
    return addresses
