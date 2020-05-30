from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('print',
                                   description='prints the current '
                                               'search results')
    return p


def run(segments, args, addresses, **kwargs):
    log_line = 'FA Debug Print: \n'
    for ea in addresses:
        log_line += '\t0x{:x}\n'.format(ea)
    print(log_line)
    return addresses
