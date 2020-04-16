import binascii


def index_of(needle, haystack):
    try:
        return haystack.index(needle)
    except ValueError:
        return -1


def find_raw(segments, manner, manner_args, current_ea, needle, count=None):
    addresses = []
    extra_offset = 0
    max_offset = 0xffffffff

    if manner == 'start':
        if manner_args is not None:
            count = eval(manner_args)

    elif manner in ('prev', 'next'):
        if manner_args is not None:
            max_offset = eval(manner_args)

    for segment_ea, data in segments.items():
        # TODO: support prev
        if manner in ('prev', 'next'):
            count = 1
            if (current_ea > segment_ea + len(data)) or (current_ea < segment_ea):
                # not in current segment
                continue
            else:
                extra_offset = current_ea - segment_ea + 1
                data = data[current_ea - segment_ea + 1:]

        offset = index_of(needle, data)
        # print(needle.encode('hex'), hex(segment_ea), len(data), offset)
        while offset != -1:
            address = segment_ea + offset + extra_offset

            if manner in ('prev', 'next'):
                if current_ea == 0x00F8BD35:
                    print(current_ea)
                # if offset from previous ea is too far
                if address - current_ea > max_offset:
                    return addresses

            addresses.append(address)
            extra_offset += offset+1
            data = data[offset+1:]

            if len(addresses) == count:
                # if too many addresses were found
                return addresses

            if manner == 'unique':
                if len(addresses) != 1:
                    # if was not found uniquely
                    return -1

            offset = index_of(needle, data)

    return addresses


def run(segments, manner, manner_args, current_ea, args, **kwargs):
    needle = binascii.unhexlify(''.join(args.split(' ')))
    return find_raw(segments, manner, manner_args, current_ea, needle)
