import argparse
import inspect
import os
import warnings

IDA_MODULE = False

try:
    import idc
    import ida_struct

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
        needle = bytearray(needle)
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
    ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_REGEX, payload)
    while ea != idc.BADADDR:
        yield ea
        ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_REGEX,
                             payload)


def read_memory(segments, ea, size):
    if IDA_MODULE:
        return idc.get_bytes(ea, size)

    for segment_ea, data in segments.items():
        if (ea <= segment_ea + len(data)) and (ea >= segment_ea):
            offset = ea - segment_ea
            return data[offset:offset+size]


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


def deprecated(function):
    frame = inspect.stack()[1]
    module = inspect.getmodule(frame[0])
    filename = module.__file__
    command_name = os.path.splitext(os.path.basename(filename))[0]

    warnings.warn('command: "{}" is deperected and will be removed in '
                  'the future.'.format(command_name, DeprecationWarning))
    return function


def add_struct_to_idb(name):
    idc.import_type(-1, name)


def find_or_create_struct(name):
    sid = ida_struct.get_struc_id(name)
    if sid == idc.BADADDR:
        sid = idc.add_struc(-1, name, 0)
        print("added struct \"{0}\", id: {1}".format(name, sid))
    else:
        print("struct \"{0}\" already exists, id: ".format(name, sid))

    add_struct_to_idb(name)

    return sid
