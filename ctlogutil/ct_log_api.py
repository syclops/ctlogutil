"""Interact with a CT log's API endpoints.

Author: Steve Matsumoto <stephanos.matsumoto@sporic.me>
"""
# Standard library imports
import aiohttp
import argparse
import base64
import asyncio
import json
import logging
import sys


# Local imports
from common_output import (
    DEFAULT_OUTPUT_FORMAT,
    OUTPUT_HANDLERS,
)
import common_parser
from common_http import (
    make_request,
    read_response_coro,
)


API_FORMAT = 'https://{}/ct/v1/{}'
ENDPOINT_CONFIGS = {
    'add-chain': ('POST', ['chain']),
    'add-pre-chain': ('POST', ['chain']),
    'get-sth': ('GET', []),
    'get-sth-consistency': ('GET', ['first', 'second']),
    'get-proof-by-hash': ('GET', ['hash', 'tree_size']),
    'get-entries': ('GET', ['start', 'end']),
    'get-roots': ('GET', []),
    'get-entry-and-proof': ('GET', ['leaf_index', 'tree_size'])
}


def sanitize_log_url(log_url):
    """
    Sanitize a given log URL by stripping the protocol and trailing slash.

    Args:
        log_url (str): TODO

    Returns:
        A str representing the sanitized URL.
    """
    logging.debug('Sanitizing {}'.format(log_url))
    if log_url[:7] == 'http://':
        log_url = log_url[7:]
    if log_url[:8] == 'https://':
        log_url = log_url[8:]
    if log_url[-1] == '/':
        log_url = log_url[:-1]
    return log_url


async def request_from_log(session, log, endpoint, arguments,
                           raise_error=True):
    """

    Args:
        session:
        log:
        endpoint:
        arguments:
        raise_error:

    Returns:
        An aiohttp.ClientResponse object representing the log's response (or
        None if the request results in an error).
    """
    url = API_FORMAT.format(sanitize_log_url(log), endpoint)
    (method, params) = ENDPOINT_CONFIGS[endpoint]

    # Check that the correct number of arguments were provided.
    if len(params) != len(arguments):
        logging.error('Incorrect number of arguments')
        raise ValueError(
            'Endpoint requires {} arguments but received {}'.format(
                len(params), len(arguments)))

    params_list = list(zip(params, arguments))
    return await make_request(session, url, method, params_list, raise_error)


async def process(loop, log, endpoint, arguments, output_format, out_file):
    """
    Make a request to a CT log API endpoint and write the results to a file.

    :param loop:
    :param log:
    :param endpoint:
    :param arguments:
    :param output_format:
    :param out_file:
    :return:
    """
    async with aiohttp.ClientSession(loop=loop) as session:
        response = await read_response_coro(request_from_log(session, log,
                                                             endpoint,
                                                             arguments))
    response_json = json.loads(response)
    with (open(out_file, 'w') if out_file is not None else sys.stdout) as fd:
        OUTPUT_HANDLERS[output_format](fd, response_json)


def parse(arg_list):
    parser = argparse.ArgumentParser(parents=[common_parser.PARSER])
    parser.add_argument('log', help='URL of log')
    parser.add_argument('endpoint', help='API endpoint to interact with')
    parser.add_argument('arguments', nargs=argparse.REMAINDER,
                        help='Arguments to API endpoint call')
    parser.add_argument('--output-format',
                        choices=list(OUTPUT_HANDLERS.keys()),
                        default=DEFAULT_OUTPUT_FORMAT, help='Output format')
    return parser.parse_args(arg_list)


def main(arg_list=sys.argv):
    args = parse(arg_list)
    common_parser.configure_logger(args.log_file, args.log_stream,
                                   args.log_level)
    loop = asyncio.get_event_loop()
    coro = process(loop, args.log, args.endpoint, args.arguments,
                   args.output_format, args.out_file)
    loop.run_until_complete(coro)


if __name__ == '__main__':
    main()
