from abc import ABCMeta, abstractmethod
from collections import OrderedDict
import json
import sys
import os

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

    def find_from_instructions_list(self, instructions, decremental=False):
        addresses = []
        manners = {}

        for line in instructions:
            line = line.strip()

            if len(line) == 0:
                continue

            for k, v in self.get_alias().items():
                # handle aliases
                if line.startswith(k):
                    line = line.replace(k, v)

            if ' ' in line:
                command, args = line.split(' ', 1)
            else:
                command = line
                args = ''

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
            if decremental and len(new_addresses) == 0 and len(addresses) > 0:
                return addresses

            addresses = new_addresses

        return addresses

    def get_signatures(self, symbol_name=None):
        signatures = []
        project_root = os.path.join(self._signatures_root, self._project)

        for root, dirs, files in os.walk(project_root):
            for filename in files:
                filename = os.path.join(project_root, filename)
                with open(filename) as f:
                    signature = json.load(f)

                if (symbol_name is None) or (signature['name'] == symbol_name):
                    signatures.append(signature)

        return signatures

    def find(self, symbol_name, decremental=False):
        results = set()
        signatures = self.get_signatures(symbol_name)
        if len(signatures) == 0:
            raise NotImplementedError('no signature found for: {}'.format(symbol_name))

        for sig in signatures:
            results.update(self.find_from_instructions_list(sig['instructions'], decremental=decremental))

        return results
