import binascii
import tempfile
import json
import os

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
        type_ = idc.GetStringType(addr)
        if type_ < 0 or type_ >= len(String.ASCSTR):
            raise StringParsingException()

        CALC_MAX_LEN = -1
        string = str(idc.GetString(addr, CALC_MAX_LEN, type_))

        self.xref = xref
        self.addr = addr
        self.type = type_
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

    command = 'find-bytes/or' if not verify else 'verify-bytes'

    for ea in range(start, end, opcode_size):
        mnemonic = idc.GetMnem(ea)
        if mnemonic in ('lis', 'lwz', 'bl') or mnemonic.startswith('b'):
            pass
        else:
            signature.append('{} {}'.format(command, binascii.hexlify(idc.GetManyBytes(ea, opcode_size))))
            if first:
                first = False
                command = 'verify-bytes'

        signature.append('add {}'.format(opcode_size))

    signature.append('add {}'.format(start - end))

    return signature


def create_signature_arm(start, end, inf, verify=True):
    """
    Create a signature for ARM processors.
    :param int start: Function's start address.
    :param int end: Function's end address.
    :param inf: IDA info object.
    :param bool verify: True of only verification required.
    False if searching is required too.
    :return: Signature steps to validate the function
    :rtype: list
    """
    instructions = []
    ea = start
    while ea < end:
        mnemonic = idc.GetMnem(ea)
        opcode_size = idautils.DecodeInstruction(ea).size
        # Skip memory accesses and branches.
        if mnemonic not in ('LDR', 'STR', 'BL', 'B', 'BLX', 'BX', 'BXJ'):
            command = 'find-bytes/or' if not verify and ea == start else 'verify-bytes'
            instructions.append('{} {}'.format(
                command,
                binascii.hexlify(idc.GetManyBytes(ea, opcode_size)))
            )
        ea += opcode_size
        instructions.append('add {}'.format(opcode_size))

    instructions.append('add {}'.format(start - end))
    return instructions


SIGNATURE_CREATION_BY_ARCH = {
    'PPC': create_signature_ppc32,
    'ARM': create_signature_arm,
}


def find_function_strings(func_ea):
    end_ea = idc.FindFuncEnd(func_ea)
    if end_ea == idaapi.BADADDR:
        return []

    strings = []
    for line in idautils.Heads(func_ea, end_ea):
        refs = idautils.DataRefsFrom(line)
        for ref in refs:
            try:
                strings.append(String(line, ref))
            except StringParsingException:
                continue

    return strings


class IdaLoader(fa.FA):
    def __init__(self):
        super(IdaLoader, self).__init__()

    def create_symbol(self):
        """
        Create a temporary symbol signature from the current function on the
        IDA screen.
        """
        self.log('creating temporary signature')
        func_start = idc.GetFunctionAttr(idc.ScreenEA(), idc.FUNCATTR_START)
        func_end = idc.GetFunctionAttr(idc.ScreenEA(), idc.FUNCATTR_END)

        signature = {
            'name': idc.GetFunctionName(idc.ScreenEA()),
            'type': 'function',
            'instructions': []
        }

        # first try adding references to strings
        strings = find_function_strings(func_start)

        strings_addr_set = set()

        for s in strings:
            if s.addr not in strings_addr_set:
                # link each string ref only once
                strings_addr_set.add(s.addr)
                signature['instructions'].append(
                    'xrefs-to/or,function-start {}'.format(s.get_bytes_for_find())
                )

        inf = idaapi.get_inf_structure()
        proc_name = inf.procName

        if proc_name not in SIGNATURE_CREATION_BY_ARCH:
            if len(signature) == 0:
                self.log('failed to create signature')
                return

        signature['instructions'] += SIGNATURE_CREATION_BY_ARCH[proc_name](
            func_start, func_end, inf, verify=len(signature) != 0
        )

        with open(TEMP_SIG_FILENAME, 'w') as f:
            json.dump(signature, f, indent=4)

        self.log('Signature created at {}'.format(TEMP_SIG_FILENAME))

    def find_symbol(self):
        """
        Find the last create symbol signature.
        :return:
        """
        for address in self.find_from_sig_path(
                TEMP_SIG_FILENAME, decremental=True):
            fa.FA.log('Search result: 0x{:x}'.format(address))

        fa.FA.log('Search done')

    def symbols(self):
        for sig in self.get_signatures():
            symbol_values = self.find(sig['name'], decremental=True)

            if len(symbol_values) == 1:
                print('0x{:08x} {}'.format(symbol_values[0], sig['name']))

    def set_input(self, input_):
        self._endianity = '>' if _idaapi.cvar.inf.mf else '<'
        self._input = input_
        self.reload_segments()

    def reload_segments(self):
        for segment_ea in idautils.Segments():
            buf = idc.GetManyBytes(
                segment_ea, idc.SegEnd(segment_ea) - segment_ea
            )
            if buf is not None:
                self.log('Loaded segment 0x{:x}'.format(segment_ea))
                self._segments[segment_ea] = buf


if __name__ == '__main__':
    fa.FA.log('''---------------------------------
FA Loaded successfully

Quick usage:
fa_instance.set_project(project_name) # select project name
print(fa_instance.list_projects()) # prints available projects
print(fa_instance.find(symbol_name)) # searches for the specific symbol
---------------------------------''')
    fa_instance = IdaLoader()
    fa_instance.set_input('ida')
    fa_instance.set_project('test-project')
    idaapi.add_hotkey('Ctrl-8', fa_instance.create_symbol)
    idaapi.add_hotkey('Ctrl-9', fa_instance.find_symbol)
