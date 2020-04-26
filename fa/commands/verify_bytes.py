import binascii

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('--until', type=int)
    p.add_argument('hex_str')
    return p


def run(segments, args, addresses, **kwargs):
    magic = binascii.unhexlify(''.join(args.hex_str.split(' ')))

    results = [ea for ea in addresses
               if utils.read_memory(segments, ea, len(magic)) == magic]

    if len(results) > 0:
        return results

    if 'until' in args:
        step = args.until
        while len(results) == 0:
            addresses = [ea + step for ea in addresses]
            results = [ea for ea in addresses
                       if utils.read_memory(segments, ea, len(magic)) == magic]

    return results
