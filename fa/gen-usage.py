from fa.fainterp import FaInterp
import os

COMMANDS_ROOT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'commands')


def main():
    for filename in os.listdir(COMMANDS_ROOT):
        command = os.path.splitext(filename)[0]
        command = FaInterp.get_command(command)
        command.print_usage()


if __name__ == '__main__':
    main()
