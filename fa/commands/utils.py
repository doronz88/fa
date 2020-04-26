import argparse

IDA_MODULE = False

try:
    import idc

    IDA_MODULE = True
except ImportError:
    pass


def index_of(needle, haystack):
    try:
        return haystack.index(needle)
    except ValueError:
        return -1


def find_raw(segments, needle):
    if IDA_MODULE:
        # ida optimization
        payload = ' '.join(['{:02x}'.format(b) for b in needle])
        return ida_find_all(payload)

    addresses = []

    for segment_ea, data in segments.items():
        offset = index_of(needle, data)
        extra_offset = 0

        while offset != -1:
            address = segment_ea + offset + extra_offset
            addresses.append(address)

            extra_offset += offset+1
            data = data[offset+1:]

            offset = index_of(needle, data)

    return addresses


def ida_find_all(payload):
    retval = []
    ea = idc.FindBinary(0, idc.SEARCH_DOWN | idc.SEARCH_REGEX, payload)
    while ea != idc.BADADDR:
        retval.append(ea)
        ea = idc.FindBinary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_REGEX,
                            payload)

    return retval


def read_memory(segments, ea, size):
    for segment_ea, data in segments.items():
        if (ea <= segment_ea + len(data)) and (ea >= segment_ea):
            offset = ea - segment_ea
            return data[offset:offset+size]


def verify_ida():
    if not IDA_MODULE:
        raise Exception("only available in IDA")


class ArgumentParserNoExit(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)
