#!/usr/bin/python
import os
import socket
import subprocess
from collections import namedtuple

import click
import IPython
import rpyc
from termcolor import cprint

IDA_PLUGIN_PATH = os.path.abspath(os.path.join((os.path.dirname(__file__), 'ida_plugin.py')))

TerminalProgram = namedtuple('TerminalProgram', 'executable args')


def is_windows():
    return os.name == 'nt'


SUPPORTED_TERMINALS = [
    TerminalProgram(executable='kitty', args=['bash', '-c']),
    TerminalProgram(executable='gnome-terminal', args=['-x', 'bash', '-c']),
    TerminalProgram(executable='xterm', args=['-e']),
]


def get_free_port():
    s = socket.socket()
    s.bind(('', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def does_program_exist(program):
    return 0 == subprocess.Popen(['which', program]).wait()


def execute_in_new_terminal(cmd):
    if is_windows():
        subprocess.Popen(cmd)
        return

    for terminal in SUPPORTED_TERMINALS:
        if does_program_exist(terminal.executable):
            subprocess.Popen([terminal.executable] + terminal.args + [' '.join(cmd)])
            return


def get_client(ida, payload, loader=None, processor_type=None, accept_defaults=False, log_file_path=None):
    port = get_free_port()
    args = [ida]

    if processor_type is not None:
        args.append('-p{}'.format(processor_type))

    if loader is not None:
        args.append('-T{}'.format(loader))

    if log_file_path is not None:
        args.append('-L{}'.format(log_file_path))

    if accept_defaults:
        args.append('-A')

    args.append('\'-S{} --service {}\''.format(IDA_PLUGIN_PATH, port))
    args.append(payload)

    execute_in_new_terminal(args)

    while True:
        try:
            client = rpyc.connect('localhost', port, config={
                # this is meant to disable the timeout
                'sync_request_timeout': None,
                'allow_all_attrs': True,
                'allow_setattr': True,
            })
            break
        except socket.error:
            pass

    return client


def launch_ida_in_service_mode(ida, payload, loader=None):
    client = get_client(ida, payload, loader)
    cprint('use `client.root` variable to access the remote object', 'cyan')
    IPython.embed()
    client.close()


@click.command()
@click.argument('ida', type=click.Path(exists=True))
@click.argument('payload', type=click.Path(exists=True))
@click.option('-l', '--loader', required=False)
def shell(ida, payload, loader):
    launch_ida_in_service_mode(ida, payload, loader)


if __name__ == '__main__':
    shell()
