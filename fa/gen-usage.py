import os
import sys

sys.path.append('.')  # noqa: E402

from fa.fainterp import FaInterp

COMMANDS_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'commands')


def main():
    for filename in os.listdir(COMMANDS_ROOT):
        if filename.endswith('.py') and \
                filename not in ('__init__.py',):
            command = os.path.splitext(filename)[0]
            command = FaInterp.get_command(command)

            p = command.get_parser()
            print('#### {}\n```\n{}```\n'.format(p.prog, p.format_help()))


if __name__ == '__main__':
    main()
