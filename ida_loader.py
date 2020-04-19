import binascii
import tempfile
import operator
import re
import os

from capstone import *
import idautils
import _idaapi
import idaapi
import idc

from fa import fa
reload(fa)

TEMP_SIG_FILENAME = os.path.join(tempfile.gettempdir(), 'fa_tmp_sig.sig')
IS_BE = '>' if _idaapi.cvar.inf.mf else '<'


class StringParsingException(Exception):
    pass


class String(object):
    ASCSTR = ["C",
              "Pascal",
              "LEN2",
              "Unicode",
              "LEN4",
              "ULEN2",
              "ULEN4"]

    def __init__(self, xref, addr):
        type = idc.GetStringType(addr)
        if type < 0 or type >= len(String.ASCSTR):
            raise StringParsingException()

        CALC_MAX_LEN = -1
        string = str(idc.GetString(addr, CALC_MAX_LEN, type))

        self.xref = xref
        self.addr = addr
        self.type = type
        self.string = string

    def get_bytes_for_find(self):
        retval = ''
        if self.ASCSTR[self.type] == 'C':
            for c in self.string + '\x00':
                retval += '{:02x} '.format(ord(c))
        else:
            raise Exception("not yet supported string")
        return retval


def create_signature_ppc32(start, end, inf, verify=True):
    signature = []
    opcode_size = 4
    first = True

    command = 'find-bytes' if not verify else 'verify'

    for ea in range(start, end, opcode_size):
        mnemonic = idc.GetMnem(ea)
        if mnemonic in ('lis', 'lwz', 'bl') or mnemonic.startswith('b'):
            pass
        else:
            signature.append('{} {} \n'.format(command, binascii.hexlify(idc.GetManyBytes(ea, opcode_size))))
            if first:
                first = False
                command = 'verify'

        signature.append('add {} \n'.format(opcode_size))

    signature.append('add {}\n'.format(start - end))

    return signature


SIGNATURE_CREATION_BY_ARCH = {
    'PPC': create_signature_ppc32,
}


def find_function_strings(func_ea):
    end_ea = idc.FindFuncEnd(func_ea)
    if end_ea == idaapi.BADADDR:
        return

    strings = []
    for line in idautils.Heads(func_ea, end_ea):
        refs = idautils.DataRefsFrom(line)
        for ref in refs:
            try:
                strings.append(String(line, ref))
            except StringParsingException:
                continue

    return strings


def create():
    global fa_instance

    fa_instance.log('creating temporary signature')
    func_start = idc.GetFunctionAttr(idc.ScreenEA(), idc.FUNCATTR_START)
    func_end = idc.GetFunctionAttr(idc.ScreenEA(), idc.FUNCATTR_END)

    signature = []

    # first try adding references to strings
    strings = find_function_strings(func_start)

    strings_addr_set = set()

    for s in strings:
        if s.addr not in strings_addr_set:
            # link each string ref only once
            strings_addr_set.add(s.addr)
            signature.append('xrefs-to/or {}\n'.format(s.get_bytes_for_find()))

    inf = idaapi.get_inf_structure()
    proc_name = inf.procName

    if proc_name not in SIGNATURE_CREATION_BY_ARCH:
        if len(signature) == 0:
            fa.FA.log('failed to create signature')
            return

    signature += SIGNATURE_CREATION_BY_ARCH[proc_name](func_start, func_end, inf, verify=True)

    with open(TEMP_SIG_FILENAME, 'w') as f:
        f.writelines(signature)

    print(TEMP_SIG_FILENAME)


def find():
    global fa_instance

    for address in fa_instance.find_from_sig_file(TEMP_SIG_FILENAME):
        fa.FA.log('Search result: 0x{:x}'.format(address))
    fa.FA.log('Search done')


def add_hotkeys():
    idaapi.add_hotkey('Ctrl-8', create)
    idaapi.add_hotkey('Ctrl-9', find)


def test(fa_instance):
    fa_instance.set_project('test-project')
    # for s in ('something1', 'something2', 's3', 's4'):
    #     fa.log(s)
    #     for ea in fa.find(s):
    #         fa.log('retval: ' + hex(ea))


if __name__ == '__main__':
    fa.FA.log('''---------------------------------
FA Loaded successfully

Quick usage:
fa_instance.set_project(project_name) # select project name
print(fa_instance.list_projects()) # prints available projects
print(fa_instance.find(symbol_name)) # searches for the specific symbol
---------------------------------''')
    fa_instance = fa.FA()
    fa_instance.set_input('ida')

    test(fa_instance)
    add_hotkeys()
