import binascii

from fa.commands import find_bytes


def get_parser():
    p = find_bytes.get_parser()
    p.add_argument('--null-terminated', action='store_true')
    return p


def run(segments, args, addresses, **kwargs):
    setattr(args, 'hex_str', binascii.hexlify(args.hex_str) + '00' if args.null_terminated else '')
    return find_bytes.run(segments, args, addresses, **kwargs)
