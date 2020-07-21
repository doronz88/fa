from tkinter import ttk, Tk
from configparser import ConfigParser

from abc import ABCMeta, abstractmethod
from collections import OrderedDict
import shlex
import sys
import os

import hjson

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'config.ini')
DEFAULT_SIGNATURES_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'signatures')
COMMANDS_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'commands')


class FaInterp:
    """
    FA Interpreter base class
    """
    __metaclass__ = ABCMeta

    def __init__(self, config_path=CONFIG_PATH):
        """
        Constructor
        :param config_path: config.ini path. used to load global settings
                            instead of setting each of the options manually
                            (signatures_root, project, ...)
        """
        self._project = None
        self._input = None
        self._segments = OrderedDict()
        self._signatures_root = DEFAULT_SIGNATURES_ROOT
        self._symbols = {}
        self.history = []
        self.checkpoints = {}
        self.endianity = '<'
        self._config_path = config_path

        if (config_path is not None) and (os.path.exists(config_path)):
            self._signatures_root = os.path.expanduser(
                self.config_get('global', 'signatures_root'))
            self._project = self.config_get('global', 'project', None)

    @abstractmethod
    def set_input(self, input_):
        """
        Set file input
        :param input_: file to work on
        :return:
        """
        pass

    def config_get(self, section, key, default=None):
        """
        Read configuration setting. This is loaded from INI config file.
        :param section: section name
        :param key: key name
        :param default: default value, if key doesn't exist inside section
        :return: the value in the specified section-key
        """
        if not os.path.exists(self._config_path):
            return default

        config = ConfigParser()

        with open(self._config_path) as f:
            config.read_file(f)

        if not config.has_section(section) or \
                not config.has_option(section, key):
            return default

        return config.get(section, key)

    def config_set(self, section, key, value):
        """
        Write configuration setting. This is saved into INI config file
        :param section: section name
        :param key: key name
        :param value: value to set
        :return: None
        """
        config = ConfigParser()

        if sys.version[0] == '2':
            section = section.decode('utf8')
            key = key.decode('utf8')
            value = value.decode('utf8')

        if os.path.exists(self._config_path):
            config.read(self._config_path)

        if not config.has_section(section):
            config.add_section(section)

        config.set(section, key, value)

        with open(self._config_path, 'w') as f:
            config.write(f)

    def set_signatures_root(self, path, save=False):
        """
        Change signatures root path (where the projects are searched).
        :param path: signatures root path (where the projects are searched).
        :param save: should save into configuration file?
        :return: None
        """
        self.log('signatures root: {}'.format(path))
        self._signatures_root = path

        if save:
            self.config_set('global', 'signatures_root', path)

    def verify_project(self):
        """
        Throws IOError if no project has been selected or points into an
        invalid path
        :return: None
        """
        if self._project is None:
            raise IOError('No project has been selected')

        if not os.path.exists(os.path.join(self._signatures_root,
                                           self._project)):
            raise IOError("Selected project's path doesn't exist.\n"
                          "Please re-select)")

    def set_project(self, project, save=True):
        """
        Set currently active project (where SIG files are placed)
        :param project: project name
        :param save: should save this setting into configuration file?
        :return: None
        """
        self._project = project
        self.log('project set: {}'.format(project))

        self.set_signatures_root(self._signatures_root, save=save)
        if save:
            self.config_set('global', 'project', project)

    def symbols(self):
        """
        Run find for all SIG files in currently active project
        :param output_file_path: optional, save found symbols into output file
        :return: dictionary of found symbols
        """
        self.get_python_symbols()

        for sig in self.get_json_signatures():
            self.find(sig['name'])

        return self._symbols

    def interactive_set_project(self):
        """
        Show GUI for selecting a project from signatures_root
        :return: None
        """
        app = Tk()
        # app.geometry('200x30')

        label = ttk.Label(app,
                          text="Choose current project")
        label.grid(column=0, row=0)

        combo = ttk.Combobox(app,
                             values=self.list_projects())
        combo.grid(column=0, row=1)

        def combobox_change_project(event):
            self.set_project(combo.get())

        combo.bind("<<ComboboxSelected>>", combobox_change_project)

        app.mainloop()

    def list_projects(self):
        """
        Get a list of all available projects in signatures_root
        :return: list of all available projects in signatures_root
        """
        projects = []
        for root, dirs, files in os.walk(self._signatures_root):
            projects += \
                [os.path.relpath(os.path.join(root, filename),
                                 self._signatures_root) for filename in dirs]
        return [str(p) for p in projects if p[0] != '.']

    @staticmethod
    def log(message):
        """
        Log message
        :param message:
        :return:
        """
        for line in message.splitlines():
            print('FA> {}'.format(line))

    @abstractmethod
    def reload_segments(self):
        """
        Reload memory segments
        :return:
        """
        pass

    @staticmethod
    def get_module(name, filename):
        """
        Load a python module by filename
        :param name: module name
        :param filename: module filename
        :return: loaded python module
        """
        if not os.path.exists(filename):
            raise NotImplementedError("no such filename: {}".format(filename))

        if sys.version == '3':
            # TODO: support python 3.0-3.4
            import importlib.util
            spec = importlib.util.spec_from_file_location(name, filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            import imp
            module = imp.load_source(name, filename)

        return module

    @staticmethod
    def get_command(command):
        """
        Get fa command as a loaded python-module
        :param command: command name
        :return: command's python-module
        """
        filename = os.path.join(COMMANDS_ROOT, "{}.py".format(command))
        return FaInterp.get_module(command, filename)

    def run_command(self, command, addresses):
        """
        Run fa command with given address list and output the result
        :param command: fa command name
        :param addresses: input address list
        :return: output address list
        """
        args = ''
        if ' ' in command:
            command, args = command.split(' ', 1)
            args = shlex.split(args)

        command = command.replace('-', '_')

        module = self.get_command(command)
        p = module.get_parser()
        args = p.parse_args(args)
        return module.run(self._segments, args, addresses,
                          interpreter=self)

    def get_alias(self):
        """
        Get dictionary of all defined aliases globally and by project.
        Project aliases loaded last so are considered stronger.
        :return: dictionary of all fa command aliases
        """
        retval = {}
        with open(os.path.join(COMMANDS_ROOT, 'alias')) as f:
            for line in f.readlines():
                line = line.strip()
                k, v = line.split('=')
                retval[k.strip()] = v.strip()

        if self._project:
            # include also project alias
            project_root = os.path.join(self._signatures_root, self._project)
            project_alias_filename = os.path.join(project_root, 'alias')
            if os.path.exists(project_alias_filename):
                with open(project_alias_filename) as f:
                    for line in f.readlines():
                        line = line.strip()
                        k, v = line.split('=')
                        retval[k.strip()] = v.strip()

        return retval

    def save_signature(self, signature):
        """
        Save given signature object (by dictionary) into active project
        as a new SIG file. If symbol name already exists, then create another
        file (never overwrites).
        :param signature: Dictionary of signature object
        :return: None
        """
        filename = os.path.join(
            self._signatures_root,
            self._project,
            signature['name'] + '.sig')
        i = 1
        while os.path.exists(filename):
            filename = os.path.join(self._signatures_root, self._project,
                                    signature['name'] + '.{}.sig'.format(i))
            i += 1

        with open(filename, 'w') as f:
            hjson.dump(signature, f, indent=4)

    def find_from_instructions_list(self, instructions,
                                    decremental=False, addresses=None):
        """
        Run the given instruction list and output the result
        :param instructions: instruction list
        :param decremental: should stop and return the output *before* the last
                            command that returned an empty list of results
        :param addresses: input address list (if any)
        :return: output address list
        """
        if addresses is None:
            addresses = []

        self.history = []
        self.checkpoints = {}

        for line in instructions:
            line = line.strip()

            if len(line) == 0:
                continue

            if line.startswith('#'):
                # treat as comment
                continue

            if line == 'stop-if-empty':
                if len(addresses) == 0:
                    return addresses
                else:
                    continue

            # normal commands

            for k, v in self.get_alias().items():
                # handle aliases
                if line.startswith(k):
                    line = line.replace(k, v)

            new_addresses = []
            try:
                new_addresses = self.run_command(line, addresses)
            except ImportError as m:
                FaInterp.log('failed to run: {}. error: {}'
                             .format(line, str(m)))

            if decremental and len(new_addresses) == 0 and len(addresses) > 0:
                return addresses

            addresses = new_addresses
            self.history.append(addresses)

        return addresses

    def find_from_sig_json(self, signature_json, decremental=False):
        """
        Find a signature from a signature JSON data.
        :param dict signature_json: Data of signature's JSON.
        :param bool decremental:
        :return: Addresses of matching signatures.
        :rtype: result list of last returns instruction
        """
        return self.find_from_instructions_list(
            signature_json['instructions'], decremental)

    def find_from_sig_path(self, signature_path, decremental=False):
        """
        Find a signature from a signature file path.
        :param str signature_path: Path to a signature file.
        :param bool decremental:
        :return: Addresses of matching signatures.
        :rtype: result list of last returns instruction
        """
        local_path = os.path.join(
            self._signatures_root, self._project, signature_path)
        if os.path.exists(local_path):
            # prefer local signatures, then external
            signature_path = local_path

        with open(signature_path) as f:
            sig = hjson.load(f)
        return self.find_from_sig_json(sig, decremental)

    def get_python_symbols(self, file_name=None):
        """
        Run all python scripts found in currently active project and return
        the dictionary of all found symbols
        :param file_name: optional, specify which python script to execute
                          inside the currently active project
        :return: dictionary of all found symbols
        """
        project_root = os.path.join(self._signatures_root, self._project)
        sys.path.append(project_root)

        for root, dirs, files in os.walk(project_root):
            for filename in files:
                if not filename.lower().endswith('.py'):
                    continue

                if not file_name or file_name == filename:
                    name = os.path.splitext(filename)[0]
                    filename = os.path.join(project_root, filename)
                    m = FaInterp.get_module(name, filename)
                    m.run(interpreter=self)

    def get_json_signatures(self, symbol_name=None):
        """
        Get a list of all json SIG objects in currently active project.
        :param symbol_name: optional, select a specific SIG file by symbol name
        :return: list of all json SIG objects in currently active project.
        """
        signatures = []
        project_root = os.path.join(self._signatures_root, self._project)

        for root, dirs, files in os.walk(project_root):
            for filename in files:
                if not filename.lower().endswith('.sig'):
                    continue

                filename = os.path.join(project_root, filename)
                with open(filename) as f:
                    try:
                        signature = hjson.load(f)
                    except ValueError as e:
                        self.log('error in json: {}'.format(filename))
                        raise e

                if (symbol_name is None) or (signature['name'] == symbol_name):
                    signatures.append(signature)

        return signatures

    def set_symbol(self, symbol_name, value):
        self._symbols[symbol_name] = value

    def find(self, symbol_name, decremental=False):
        """
        Find symbol by its name in the SIG file
        :param symbol_name: symbol name
        :param decremental: Should stop *before* the last command which
                            returned zero results
        :return: list of matches for the given symbol
        """
        results = []
        signatures = self.get_json_signatures(symbol_name)
        if len(signatures) == 0:
            raise NotImplementedError('no signature found for: {}'
                                      .format(symbol_name))

        for sig in signatures:
            sig_results = self.find_from_sig_json(sig)

            if isinstance(sig_results, dict):
                if symbol_name in sig_results:
                    results += sig_results[symbol_name]
            else:
                results += sig_results

        return list(set(results))
