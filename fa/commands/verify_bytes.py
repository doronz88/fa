import binascii

from fa.commands import utils


def run(segments, manners, addresses, args, **kwargs):
    magic = binascii.unhexlify(''.join(args.split(' ')))

    results = [ea for ea in addresses if utils.read_memory(segments, ea, len(magic)) == magic]

    if len(results) > 0:
        return results

    if 'until' in manners.keys():
        step = 1
        if manners['until']:
            step = eval(manners['until'])
        while len(results) == 0:
            addresses = [ea + step for ea in addresses]
            results = [ea for ea in addresses if utils.read_memory(segments, ea, len(magic)) == magic]

    return results
