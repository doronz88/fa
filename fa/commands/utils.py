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


def find_raw(needle, segments=None):
    if segments is None:
        segments = dict()

    if IDA_MODULE:
        # ida optimization
        payload = ' '.join(['{:02x}'.format(b) for b in needle])
        for address in ida_find_all(payload):
            yield address
        return

    for segment_ea, data in segments.items():
        offset = index_of(needle, data)
        extra_offset = 0

        while offset != -1:
            address = segment_ea + offset + extra_offset
            yield address

            extra_offset += offset+1
            data = data[offset+1:]

            offset = index_of(needle, data)


def ida_find_all(payload):
    ea = idc.FindBinary(0, idc.SEARCH_DOWN | idc.SEARCH_REGEX, payload)
    while ea != idc.BADADDR:
        yield ea
        ea = idc.FindBinary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_REGEX,
                            payload)


def read_memory(segments, ea, size):
    for segment_ea, data in segments.items():
        if (ea <= segment_ea + len(data)) and (ea >= segment_ea):
            offset = ea - segment_ea
            return data[offset:offset+size]


def verify_ida():
    if not IDA_MODULE:
        raise Exception("only available in IDA")


def yield_unique(func):
    def wrapper(*args, **kwargs):
        results = set()
        for i in func(*args, **kwargs):
            if i not in results:
                yield i
                results.add(i)
    return wrapper


class ArgumentParserNoExit(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)
