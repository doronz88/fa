from abc import ABCMeta, abstractmethod
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

DEFAULT_MANNER = 'or'
NON_REDUCING_MANNERS = ('or', )
NON_REDUCING_COMMANDS = ('find_bytes', 'powerpc_find_opcodes')

MULTILINE_PREFIX = '    '


class FA:
    __metaclass__ = ABCMeta

    def __init__(self, signatures_root=SIGNATURES_ROOT):
        self._signatures_root = signatures_root
        self._project = 'generic'
        self._input = None
        self._segments = OrderedDict()
        self._endianity = '<'

    @abstractmethod
    def set_input(self, input_):
        pass

    def set_project(self, project):
        self._project = project

    def list_projects(self):
        projects = []
        for project_dirname in os.listdir(self._signatures_root):
            project_fullpath = os.path.join(self._signatures_root, project_dirname)

            if os.path.isdir(project_fullpath):
                projects.append(project_dirname)

        return projects

    def get_symbols(self):
        symbols_dir = os.path.join(self._signatures_root, self._project)
        return [os.path.splitext(filename)[0] for filename in os.listdir(symbols_dir)]

    @staticmethod
    def log(message):
        for line in message.splitlines():
            print('FA> {}'.format(line))

    @abstractmethod
    def reload_segments(self):
        pass

    def run_command(self, command, manners, current_ea, args):
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

        return module.run(self._segments, manners, current_ea, args, endianity=self._endianity)

    @staticmethod
    def get_alias():
        retval = {}
        with open(os.path.join(COMMANDS_ROOT, 'alias')) as f:
            for line in f.readlines():
                line = line.strip()
                k, v = line.split('=')
                retval[k.strip()] = v.strip()
        return retval

    def find_from_sig_file(self, symbol_sig_filename, decremental=False):
        if not os.path.exists(symbol_sig_filename):
            raise NotImplementedError("no signature for the given symbol")

        addresses = []
        instructions = []
        manners = {}

        with open(symbol_sig_filename) as f:
            instruction_lines_raw = f.readlines()

        for line in instruction_lines_raw:
            if len(line) == 0:
                continue

            line = line.replace('\t', MULTILINE_PREFIX)
            if line.startswith(MULTILINE_PREFIX):
                if len(instructions) == 0:
                    raise ValueError("line-continuation without a first line")
                instructions[-1] += line.split(MULTILINE_PREFIX, 1)[1].strip()
            else:
                instructions.append(line.strip())

        for line in instructions:
            line = line.strip()

            if len(line) == 0:
                continue

            if '#' in line:
                line, comment = line.split('#', 1)

            for k, v in self.get_alias().items():
                # handle aliases
                if line.startswith(k):
                    line = line.replace(k, v)

            if ' ' in line:
                command, args = line.split(' ', 1)
            else:
                command = line
                args = ''

            manner = DEFAULT_MANNER

            if '/' in command:
                # parse manners
                command, manners_raw = command.split('/', 1)
                for manner_raw in manners_raw.split(','):
                    manner = manner_raw
                    manner_args = ''
                    if '{' in manner:
                        manner, manner_args = manners_raw.split('{')
                        manner_args = manner_args.split('}')[0]
                    manners[manner] = manner_args

            new_addresses = self.run_command(command, manners, addresses, args)

            if decremental and len(new_addresses) == 0:
                if (manner not in NON_REDUCING_MANNERS) and (command not in NON_REDUCING_COMMANDS):
                    # these commands never reduce the number of results
                    return addresses

            addresses = new_addresses

        return addresses

    def find(self, symbol_name):
        symbol_sig_filename = os.path.join(self._signatures_root, self._project, '{}.sig'.format(symbol_name))
        return self.find_from_sig_file(symbol_sig_filename)
