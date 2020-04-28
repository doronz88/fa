from abc import ABCMeta, abstractmethod
from collections import OrderedDict
import shlex
import json
import sys
import os

from fa.commands.function_start import get_function_start

SIGNATURES_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'signatures')
COMMANDS_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'commands')

MULTILINE_PREFIX = '    '


class FaInterp:
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
            project_fullpath = os.path.join(
                self._signatures_root, project_dirname)

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

    @staticmethod
    def get_command(command):
        filename = os.path.join(COMMANDS_ROOT, "{}.py".format(command))

        if not os.path.exists(filename):
            raise NotImplementedError("no such command: {}".format(command))

        if sys.version == '3':
            # TODO: support python 3.0-3.4
            import importlib.util
            spec = importlib.util.spec_from_file_location(command, filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            import imp
            module = imp.load_source(command, filename)

        return module

    def run_command(self, command, addresses):
        args = ''
        if ' ' in command:
            command, args = command.split(' ', 1)
            command = command.replace('-', '_')
            args = shlex.split(args)

        module = self.get_command(command)
        p = module.get_parser()
        args = p.parse_args(args)
        return module.run(self._segments, args, addresses,
                          endianity=self._endianity)

    @staticmethod
    def get_alias():
        retval = {}
        with open(os.path.join(COMMANDS_ROOT, 'alias')) as f:
            for line in f.readlines():
                line = line.strip()
                k, v = line.split('=')
                retval[k.strip()] = v.strip()
        return retval

    def save_signature(self, signature):
        filename = os.path.join(self._signatures_root, self._project, signature['name'] + '.sig')
        i = 1
        while os.path.exists(filename):
            filename = os.path.join(self._signatures_root, self._project,
                                    signature['name'] + '.{}.sig'.format(i))
            i += 1

        with open(filename, 'w') as f:
            json.dump(signature, f, indent=4)

    def find_from_instructions_list(self, instructions, decremental=False):
        addresses = []

        for line in instructions:
            line = line.strip()

            if len(line) == 0:
                continue

            if line.startswith('#'):
                # treat as comment
                continue

            for k, v in self.get_alias().items():
                # handle aliases
                if line.startswith(k):
                    line = line.replace(k, v)

            new_addresses = self.run_command(line, addresses)
            if decremental and len(new_addresses) == 0 and len(addresses) > 0:
                return addresses

            addresses = new_addresses

        return addresses

    def find_from_sig_json(self, signature_json, decremental=False):
        """
        Find a signature from a signature JSON data.
        :param dict signature_json: Data of signature's JSON.
        :param bool decremental:
        :return: Addresses of matching signatures.
        :rtype: list
        """
        return self.find_from_instructions_list(
            signature_json['instructions'], decremental
        )

    def find_from_sig_path(self, signature_path, decremental=False):
        """
        Find a signature from a signature file path.
        :param str signature_path: Path to a signature file.
        :param bool decremental:
        :return: Addresses of matching signatures.
        :rtype: list
        """
        with open(signature_path) as f:
            sig = json.load(f)
        return self.find_from_sig_json(sig, decremental)

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
        results = []
        signatures = self.get_signatures(symbol_name)
        if len(signatures) == 0:
            raise NotImplementedError('no signature found for: {}'
                                      .format(symbol_name))

        for sig in signatures:
            sig_results = self.find_from_instructions_list(
                sig['instructions'], decremental=decremental)

            if sig['type'] == 'function':
                sig_results = [get_function_start(self._segments, ea)
                               for ea in sig_results]

            results += sig_results

        return list(OrderedDict.fromkeys(results))
