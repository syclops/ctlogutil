"""
Define common command-line options and handle these options.

This module provides a common set of command-line options shared among all
ctlogutil tools (namely, logging settings).

Author: Steve Matsumoto <stephanos.matsumoto@sporic.me>

TODO: at some point this functionality should be incorporated into a common
abstract parent tool class that performs the necessary setup and then passes
control to a child class for the actual functionality of the tool.
"""
# Standard library imports
import argparse
import logging
import sys


# Use the standard logging levels.
LOG_LEVEL_MAP = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}
DEFAULT_LOG_LEVEL = 'warning'


def __create_common_parser():
    """Create common parser.

    Create the common parser for ctlogutil tools, which currently specifies
    logging and output settings. Specifically, allow the user to specify a file
    and/or stream to log messages to, as well as a logging level and output
    file.

    TODO: set default output file to stdout.
    """
    # We inherit from this parser so it doesn't need a help message of its own
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--log-file', help='file to write log messages to')
    parser.add_argument('--log-stream', help='stream to write log messages to')
    parser.add_argument('--log-level', choices=list(LOG_LEVEL_MAP.keys()),
                        default=DEFAULT_LOG_LEVEL, help='minimum logging level')
    parser.add_argument('--out-file', help='file to write output to')
    return parser


# Create common parser to make it available to child parsers in tool
# implementation modules.
PARSER = __create_common_parser()


def configure_logger(log_file, log_stream, log_level=DEFAULT_LOG_LEVEL):
    """Configure logging based on given settings.

    Set up logging using the given arguments (using the `logging` module in
    Python's standard library). Specifically, configure logging to use a
    given file, a given stream, and a given log level.

    Args:
        log_file (str): path to the desired log file.
        log_stream (io.TextIOWrapper): desired log stream.
        log_level (str): string representing the desired log level.

    Returns:
        None.

    TODO: implement functionality to allow multiple files and streams.
    """
    handlers = []
    if log_file is not None:
        handlers.append(logging.FileHandler(log_file))
    if log_stream is None:
        log_stream = sys.stderr
    handlers.append(logging.StreamHandler(log_stream))
    logging.basicConfig(level=LOG_LEVEL_MAP[log_level], handlers=handlers)
