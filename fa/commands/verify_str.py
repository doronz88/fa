import binascii

from fa.commands import verify_bytes


def get_parser():
    return verify_bytes.get_parser()


def run(segments, args, addresses, **kwargs):
    setattr(args, 'hex_str', binascii.hexlify(args.hex_str) + '00' if args.null_terminated else '')
    return verify_bytes.run(segments, args, addresses, **kwargs)
