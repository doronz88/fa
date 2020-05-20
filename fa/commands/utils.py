from collections import namedtuple
import argparse

IDA_MODULE = False

try:
    import idc
    import idaapi

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


def add_struct_to_idb(name):
    idc.Til2Idb(-1, name)


def find_or_create_struct(name):
    sid = idc.GetStrucIdByName(name)
    if sid == idc.BADADDR:
        sid = idc.AddStrucEx(-1, name, 0)
        print("added struct \"{0}\", id: {1}".format(name, sid))
    else:
        print("struct \"{0}\" already exists, id: ".format(name, sid))

    add_struct_to_idb(name)

    return sid


def add_const(name, value):
    id = idc.GetEnum('FA_CONSTS')
    if idc.BADADDR == id:
        id = idc.AddEnum(-1, 'FA_CONSTS', idaapi.decflag())

    idc.AddConstEx(id, name, value, -1)


class FaStruct(object):
    Field = namedtuple('Field', ['name', 'type', 'size'])

    def __init__(self, name):
        self._name = name
        self._fields = []
        self._size = 0

    def add_field(self, name, type_, size=0, offset=0):
        if (offset != 0) and (offset != self._size):
            self.add_field('padd_{:x}'.format(self._size),
                           'unsigned char[{}]'.format(offset - self._size),
                           offset - self._size)

        self._fields.append(self.Field(name, type_, size))
        self._size += size

    def update_idb(self):
        sid = idc.GetStrucIdByName(self._name)
        if sid != -1:
            idc.DelStruc(sid)
        sid = idc.AddStrucEx(-1, self._name, 0)

        for f in self._fields:
            idc.AddStrucMember(sid, f.name, -1,
                               (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, -1, 1)
            member_name = "{}.{}".format(self._name, f.name)
            idc.SetType(idaapi.get_member_by_fullname(member_name)[0].id,
                        f.type)

        idc.Wait()

    def exists(self):
        return -1 != idc.GetStrucIdByName(self._name)
