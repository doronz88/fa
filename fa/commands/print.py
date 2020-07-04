from fa import utils

DESCRIPTION = '''prints the current result-set (for debugging)'''


def get_parser():
    p = utils.ArgumentParserNoExit('print',
                                   description=DESCRIPTION)
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    log_line = 'FA Debug Print: \n'
    for ea in addresses:
        log_line += '\t0x{:x}\n'.format(ea)
    print(log_line)
    return addresses
