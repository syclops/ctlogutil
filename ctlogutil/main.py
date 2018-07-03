"""Main driver for ctlogutil, the CT log utility.

This module contains the main driver functionality for ctlogutil. The driver
simply splits the command-line arguments into a tool name and its appropriate
arguments, and then passes these items to the appropriate command handler.
The `cmd_handlers` module defines these command handlers.
"""
# Standard library imports
import argparse
import sys

# Local imports
import cmd_handlers


def parse(args=sys.argv):
    """Parse arguments sent to the command handler.

    Args:
        args (list): the arguments to pass to the parser.

    Returns:
        A `Namespace` object with the appropriate variables set.
    """
    parser = argparse.ArgumentParser(args)
    parser.add_argument('command', choices=list(cmd_handlers.HANDLERS.keys()),
                        help='tool to run')
    parser.add_argument('cmd_args', nargs=argparse.REMAINDER,
                        help='arguments to pass to command')
    return parser.parse_args()


def main():
    args = parse()
    cmd_handlers.handle(args.command, args.cmd_args)


if __name__ == '__main__':
    main()
