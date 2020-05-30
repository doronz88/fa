from abc import abstractmethod
from collections import namedtuple


try:
    import idc
    import idaapi

    IDA_MODULE = True
except ImportError:
    pass


class FaType(object):
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def exists(self):
        return -1 != idc.GetStrucIdByName(self._name)

    @abstractmethod
    def update_idb(self):
        pass


class FaEnum(FaType):
    def __init__(self, name):
        super(FaEnum, self).__init__(name)
        self._values = {}

    def add_value(self, name, value):
        self._values[value] = name

    def update_idb(self):
        id = idc.GetEnum(self._name)
        if idc.BADADDR == id:
            id = idc.AddEnum(-1, self._name, idaapi.decflag())

        keys = self._values.keys()
        keys.sort()

        for k in keys:
            idc.AddConstEx(id, self._values[k], k, -1)


class FaStruct(FaType):
    Field = namedtuple('Field', ['name', 'type', 'size'])

    def __init__(self, name):
        super(FaStruct, self).__init__(name)
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


def add_const(name, value):
    fa_consts = FaEnum('FA_CONSTS')
    fa_consts.add_value(name, value)
    fa_consts.update_idb()
