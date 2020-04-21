from collections import OrderedDict
import os
import sys

IDA_MODULE = False

try:
    import idc
    import idaapi
    import _idaapi
    import idautils

    IDA_MODULE = True
except ImportError:
    pass

SIGNATURES_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'signatures')
COMMANDS_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'commands')

NON_REDUCING_MANNERS = ('or', )
NON_REDUCING_COMMANDS = ('find_bytes', 'powerpc_find_opcodes')

class FA:
    def __init__(self, signatures_root=SIGNATURES_ROOT):
        self._signatures_root = signatures_root
        self._project = 'generic'
        self._input = None
        self._segments = OrderedDict()
        self._endianity = '<'

    def set_input(self, input_):
        if input_ == 'ida':
            self._endianity = '>' if _idaapi.cvar.inf.mf else '<'
        else:
            # TODO: handle ELF file when given
            raise NotImplementedError("currently only ida supported")

        self._input = input_
        self.reload_segments()

    def set_project(self, project):
        self._project = project

    def list_projects(self):
        projects = []
        for project_dirname in os.listdir(self._signatures_root):
            project_fullpath = os.path.join(self._signatures_root, project_dirname)

            if os.path.isdir(project_fullpath):
                projects.append(project_dirname)

        return projects

    @staticmethod
    def log(message):
        for line in message.splitlines():
            print('FA> {}'.format(line))

    def reload_segments(self):
        if self._input == 'ida':
            for segment_ea in idautils.Segments():
                buf = idc.GetManyBytes(segment_ea, idc.SegEnd(segment_ea) - segment_ea)
                if buf is not None:
                    self.log('Loaded segment 0x{:x}'.format(segment_ea))
                    self._segments[segment_ea] = buf
        else:
            raise NotImplementedError("only supported from ida")

    def run_command(self, command, manner, manner_args, current_ea, args):
        command = command.replace('-', '_')
        filename = os.path.join(COMMANDS_ROOT, "{}.py".format(command))

        if not os.path.exists(filename):
            self.log("no such command: {}".format(command))
            return -1

        if sys.version == '3':
            # TODO: support python 3.0-3.4
            import importlib.util
            spec = importlib.util.spec_from_file_location(command, filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            import imp
            module = imp.load_source(command, filename)

        return module.run(self._segments, manner, manner_args, current_ea, args, endianity=self._endianity)

    def find_from_sig_file(self, symbol_sig_filename, decremental=True):
        if not os.path.exists(symbol_sig_filename):
            raise NotImplementedError("no signature for the given symbol")

        addresses = []
        manner_args = None

        with open(symbol_sig_filename) as f:
            for line in f.readlines():
                line = line.strip()

                if len(line) == 0:
                    continue

                if '#' in line:
                    line, comment = line.split('#', 1)

                command, args = line.split(' ', 1)

                manner = 'start'

                if '{' in command:
                    manner_args = command.split('{')[1].split('}')[0]
                    command = command.split('{')[0]

                if '/' in command:
                    prefix, suffix = command.split('/', 1)
                    command = prefix
                    manner = suffix

                new_addresses = self.run_command(command, manner, manner_args, addresses, args)

                if decremental and len(new_addresses) == 0:
                    if (manner not in NON_REDUCING_MANNERS) and (command not in NON_REDUCING_COMMANDS):
                        # these commands never reduce the number of results
                        return addresses

                addresses = new_addresses

        return addresses

    def find(self, symbol_name):
        symbol_sig_filename = os.path.join(self._signatures_root, self._project, '{}.sig'.format(symbol_name))
        return self.find_from_sig_file(symbol_sig_filename)
