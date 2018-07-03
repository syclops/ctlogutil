"""
List known logs in Certificate Transparency.

Author: Steve Matsumoto <stephanos.matsumoto@sporic.me>
"""
# Standard library imports
import argparse
import asyncio
import json
import logging
import sys

# Third party imports
import aiohttp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Local imports
from common_http import (
    make_request,
    read_response_coro,
)
from common_output import (
    DEFAULT_OUTPUT_FORMAT,
    OUTPUT_HANDLERS,
)
import common_parser


# Default locations for list of known logs and signature/pubkey information.
DEFAULT_LOG_LIST = 'https://www.gstatic.com/ct/log_list/log_list.json'
DEFAULT_LOG_LIST_SIG = 'https://www.gstatic.com/ct/log_list/log_list.sig'
DEFAULT_LOG_LIST_PUBKEY = \
    'https://www.gstatic.com/ct/log_list/log_list_pubkey.pem'


# Schema for the log list JSON file.
LOG_ATTRIBUTES = [
    'description',  # The log name (str)
    'key',  # The log's base64-encoded public key (str)
    'url',  # URL of the log's REST-like API endpoint
    'maximum_merge_delay',  # The log's MMD in seconds (int)
    'operated_by',  # ID numbers of the log's operators (list(int))
    'disqualified_at',  # Unix timestamp of disqualification by Chrome (int)
    'dns_api_endpoint',  # URL where the log serves information over DNS
]


def make_operator_map(operator_dict):
    operator_map = {}
    for operator_info in operator_dict:
        operator_map[operator_info['id']] = operator_info['name']
    return operator_map


def map_operator_ids(response_dict):
    """
    Replace the log operator ids in the log dictionary with the names of the
    log operators as given in the CT known log list.

    Args:
        response_dict (dict): a representation of the JSON response.

    Returns:
        A modified dict in which the log ids are replaced with the names of
        the corresponding log operators.
    """
    # Make the list of operator names.
    operator_map = make_operator_map(response_dict['operators'])
    logging.debug('Operator map: {}'.format(operator_map))

    # Replace the operator ids with corresponding names.
    log_dict = response_dict['logs']
    for log_info in log_dict:
        operator_list = []
        for operator_id in log_info['operated_by']:
            operator_list.append(operator_map[operator_id])
        log_info['operated_by'] = operator_list
    return log_dict


def verify_list_signature(logs, sig, pubkey, sig_scheme=padding.PKCS1v15(),
                          hash_func=hashes.SHA256()):
    """Verify the signature on the list of known logs.

    By default, this function performs RSA signature verification assuming
    the PKCS1 v1.5 signature scheme specified in RFC 3447, Sec. 8.2 and
    SHA-256 to produce a digest of the list of logs.

    Args:
        logs (bytes): the text representation of the known logs JSON file.
        sig (bytes): the signature on the list of logs.
        pubkey (bytes): the public key in PEM format.
        sig_scheme (padding.AsymmetricPadding): the signature scheme to use
            (in particular, the padding scheme to use).
        hash_func (hashes.Hash): the hash function used to generate the
            digest of the log list.

    Raises:
        InvalidSignature

    Returns:
        None.
    """
    try:
        pk = serialization.load_pem_public_key(pubkey,
                                               backend=default_backend())
        pk.verify(sig, logs, sig_scheme, hash_func)
        logging.info('Verified log list signature')
    except InvalidSignature:
        logging.error('Signature on log list could not be verified.')
        logging.debug('Signature is {}'.format(sig))
        logging.debug('Public key is {}'.format(pubkey))
        raise


async def get_known_logs(loop, session, log_list, log_list_sig=None,
                         log_list_pubkey=None, verify_sig=False):
    """
    TODO: Fill this in

    Args:
        session:
        log_list:
        log_list_sig:
        log_list_pubkey:
        verify_sig:

    Returns:
        A str representing the JSON form of the known logs list.
    """
    logging.debug('Requesting known logs from {}'.format(log_list))

    # The response text is what we care about, so our future reads the response
    # content.
    log_task = read_response_coro(make_request(session, log_list,
                                               raise_error=True))

    # We need to get the log list regardless, so schedule its execution.
    log_future = asyncio.ensure_future(log_task, loop=loop)

    if verify_sig:
        logging.debug('Requesting signature on known logs from {}'.format(
            log_list_sig))
        sig_task = read_response_coro(make_request(session, log_list_sig,
                                                   raise_error=True))

        logging.debug('Requesting public key from {}'.format(log_list_pubkey))
        pubkey_task = read_response_coro(make_request(session, log_list_pubkey,
                                                      raise_error=True))

        verify_args = await asyncio.gather(log_future, sig_task, pubkey_task,
                                           loop=loop)
        verify_list_signature(*verify_args)

    response = await log_future
    return response


async def process(loop, log_list, log_list_sig, log_list_pubkey, verify_sig,
                  use_operator_names, output_format, out_file):
    """

    Args:
        loop (asyncio.unix_events._UnixSelectorEventLoop):
        log_list (str):
        log_list_sig (str):
        log_list_pubkey (str):
        verify_sig (bool):
        use_operator_names (bool):
        output_format (str):
        out_file (str):
    """
    async with aiohttp.ClientSession(loop=loop) as session:
        response = await get_known_logs(loop, session, log_list, log_list_sig,
                                        log_list_pubkey, verify_sig)
    response_dict = json.loads(response)
    if use_operator_names:
        log_dict = map_operator_ids(response_dict)
        logging.debug('Log dict: {}'.format(log_dict))
    else:
        log_dict = response_dict['logs']
    with (open(out_file, 'w') if out_file is not None else sys.stdout) as fd:
        OUTPUT_HANDLERS[output_format](fd, log_dict)


def parse(arg_list):
    parser = argparse.ArgumentParser(parents=[common_parser.PARSER])
    parser.add_argument('--log-list', default=DEFAULT_LOG_LIST,
                        help='log list URL to obtain')
    parser.add_argument('--log-sig', default=DEFAULT_LOG_LIST_SIG,
                        help='log list URL to obtain')
    parser.add_argument('--log-pub-key', default=DEFAULT_LOG_LIST_PUBKEY,
                        help='log list URL to obtain')
    parser.add_argument('--verify-sig', action='store_true',
                        help='verify signature on log list')
    parser.add_argument('--use-operator-names', action='store_true',
                        help='list log operators by name instead of id')
    parser.add_argument('--output-format',
                        choices=list(OUTPUT_HANDLERS.keys()),
                        default=DEFAULT_OUTPUT_FORMAT, help='Output format')
    return parser.parse_args(arg_list)


def main(arg_list=sys.argv):
    args = parse(arg_list)
    common_parser.configure_logger(args.log_file, args.log_stream,
                                   args.log_level)
    loop = asyncio.get_event_loop()
    coro = process(loop, args.log_list, args.log_sig, args.log_pub_key,
                   args.verify_sig, args.use_operator_names,
                   args.output_format, args.out_file)
    loop.run_until_complete(coro)


if __name__ == '__main__':
    main()
