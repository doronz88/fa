from abc import abstractmethod
from collections import namedtuple

try:
    import ida_auto
    import ida_bytes
    import ida_typeinf
    import idaapi
    import idc

    IDA_MODULE = True
except ImportError:
    IDA_MODULE = False


def del_struct_members(sid: int, offset1: int, offset2: int) -> None:
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        udm = ida_typeinf.udm_t()
        udm.offset = offset1 * 8
        idx1 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        udm = ida_typeinf.udm_t()
        udm.offset = offset2 * 8
        idx2 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        idx1 &= 0xffffffff
        idx2 &= 0xffffffff
        tif.del_udms(idx1, idx2)


class FaType(object):
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name

    def exists(self):
        return -1 != idc.get_struc_id(self._name)

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
        id = idc.get_enum(self._name)
        if idc.BADADDR == id:
            id = idc.add_enum(idc.BADADDR, self._name, ida_bytes.dec_flag())

        keys = self._values.keys()
        sorted(keys)

        for k in keys:
            idc.add_enum_member(id, self._values[k], k, 0xffffffffffffffff)


class FaStruct(FaType):
    Field = namedtuple('Field', ['name', 'type', 'offset'])

    def __init__(self, name):
        super(FaStruct, self).__init__(name)
        self._fields = []

    def add_field(self, name, type_, offset=0xffffffff):
        self._fields.append(self.Field(name, type_, offset))

    def update_idb(self, delete_existing_members: bool = True) -> None:
        sid = idc.get_struc_id(self._name)

        if sid == idc.BADADDR:
            sid = idc.add_struc(idc.BADADDR, self._name, 0)
        else:
            if delete_existing_members:
                del_struct_members(sid, 0, 0xffffffff)

        for f in self._fields:
            idc.add_struc_member(sid, f.name, f.offset, (idc.FF_BYTE | idc.FF_DATA) & 0xFFFFFFFF, 0xFFFFFFFF, 1)
            member_name = f'{self._name}.{f.name}'
            member_struct_id = idc.get_struc_id(member_name)
            idc.SetType(member_struct_id, f.type)

        ida_auto.auto_wait()


def add_const(name, value):
    fa_consts = FaEnum('FA_CONSTS')
    fa_consts.add_value(name, value)
    fa_consts.update_idb()
