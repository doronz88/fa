import binascii

from fa.commands import verify_bytes


def get_parser():
    p = verify_bytes.get_parser()
    p.add_argument('--null-terminated', action='store_true')

    p.prog = 'verify-str'
    p.description = 'reduces the search list to those matching the given string'
    return p


def run(segments, args, addresses, **kwargs):
    setattr(args, 'hex_str', binascii.hexlify(args.hex_str) + '00' if args.null_terminated else '')
    return verify_bytes.run(segments, args, addresses, **kwargs)
