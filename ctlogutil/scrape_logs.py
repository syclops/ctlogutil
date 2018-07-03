"""Scrape known CT logs.
"""
# Standard library imports
import aiohttp
import argparse
import asyncio
import base64
import fileinput
import hashlib
import json
import logging
import sys


# Local imports
from common_exception import (
    ParameterError,
)
from common_http import (
    read_response_coro,
)
import common_parser
from common_util import (
    filter_none,
)
import ct_log_api
import ct_log_formats
from list_logs import (
    DEFAULT_LOG_LIST,
    get_known_logs,
)


DEFAULT_CONN_TIMEOUT = 10
DEFAULT_DELIMITER = ','
DEFAULT_MAX_RETRIES = 5
DEFAULT_MAX_DOWNLOADS = 200
DEFAULT_INIT_QUEUE = 5 * DEFAULT_MAX_DOWNLOADS
DEFAULT_MAX_QUEUE = 10 * DEFAULT_MAX_DOWNLOADS
QUEUE_POLL_INTERVAL = 0.1


async def make_param_tuple(session, log_url, start='', end=''):
    """
    Form a request tuple: a range of entries to fetch from a particular log.

    The start and end parameters will be filled in with default values if
    not provided. Specifically, start will be assumed to be '0' (the first
    entry in the log) and end will be assumed to be the log size minus one (the
    index of the last entry in the log).

    Args:
        session (aiohttp.ClientSession): TODO
        log_url (str): TODO
        start (str): TODO
        end (str): TODO

    Returns:
        A tuple of type (str, str, str) representing the log's URL,
        the index of the first entry to retrieve from the log, and the index of
        the last entry to retrieve from the log.

    """
    if start is None or start == '':
        logging.debug('No start index given for {}; defaulting to 0'.format(
            log_url))
        start = 0
    else:
        start = int(start)
    if end is None or end == '':
        logging.debug('No end index given for {}; attempting to get log '
                      'size'.format(log_url))
        task = ct_log_api.request_from_log(session, log_url, 'get-sth', [],
                                           raise_error=False)
        response_text = await read_response_coro(task)
        if response_text is None:
            return None
        sth = json.loads(response_text)
        logging.info('{} has {} entries as of {}'.format(log_url,
                                                         sth['tree_size'],
                                                         sth['timestamp']))
        end = sth['tree_size'] - 1
    else:
        end = int(end)
    return log_url, start, end


async def process_param_file(session, loop, param_file,
                             delimiter=DEFAULT_DELIMITER):
    """
    Read a parameter file and make a list of parameter tuples.

    Args:
        session (aiohttp.ClientSession): HTTP client session used to get the
            log size if necessary.
        loop: TODO
        param_file (str): path to parameter file.
        delimiter (str): string used to delimit the log URL, starting entry,
            and ending entry in the parameter file.

    Returns:
        A list of parameter tuples as specified by the return value of
        `make_param_tuple`.

    """
    task_list = []
    for line in fileinput.input(param_file):
        logging.debug('Read line {} from parameter file'.format(line.strip()))
        log_params = line.strip().split(delimiter)
        if len(log_params) != 3:
            logging.error('Parameter file must contain lines of the form '
                          'url,start,end but {} values were provided '
                          'instead'.format(len(log_params)))
            continue
        logging.debug('Read tokens {}, {}, {} from parameter file'.format(
            *log_params))
        task_list.append(make_param_tuple(session, *log_params))
    param_tuple_list = await asyncio.gather(*task_list, loop=loop)
    return filter_none(param_tuple_list)


async def process_known_logs(session, loop):
    """
    Build the set of parameter tuples from the list of known logs.

    Build a list of (log, start_index, end_index) parameter tuples
    from the list of known CT logs. Specifically, retrieve this list from
    Google, and query each of them to find their Merkle Tree size. The
    parameter list is the set of (log, 0, tree_size) for each log.

    Args:
        session (aiohttp.ClientSession):
        loop (asyncio event loop):

    Returns:

    """
    log_dict = json.loads(await get_known_logs(loop, session,
                                               DEFAULT_LOG_LIST))
    task_list = []
    for log in log_dict['logs']:
        if is_disqualified(log):
            logging.debug('Log {} is disqualified. Skipping.'.format(
                log['description']))
            continue
        task_list.append(make_param_tuple(session, log['url']))
    param_tuple_list = await asyncio.gather(*task_list, loop=loop)

    # Due to timeouts or client errors, some connections may fail and
    # return None, so filter out those from the parameter list.
    param_list = filter_none(param_tuple_list)

    logging.info('Built parameters for {} out of {} known logs'.format(
        len(param_list), len(log_dict['logs'])))
    return param_list


def is_disqualified(log):
    """

    Args:
        log (dict):

    Returns:

    """
    return 'disqualified_at' in log


async def build_param_list(session, loop, param_file, all_known_logs, log,
                           start, end):
    """
    Build the appropriate parameter list based on the arguments given.

    Args:
        session (aiohttp.ClientSession):
        loop:
        param_file (str):
        all_known_logs (bool):
        log (str):
        start (str):
        end (str):

    Returns:
        A list of parameter tuples as specified in the return value of
        `make_param_tuple`.

    Raises:
        ParameterError if no method for constructing the parameter list is
        provided.
    """
    if param_file is not None:
        logging.debug('Processing parameter file')
        # TODO: edit the line below to use custom delimiters.
        return await process_param_file(session, loop, param_file)
    elif all_known_logs:
        logging.debug('Scraping all known logs')
        return await process_known_logs(session, loop)
    elif log is not None:
        logging.debug('Scraping single log')
        return [await make_param_tuple(session, log, start, end)]
    else:
        # This shouldn't happen because one of the
        raise ParameterError('At least one of param_file, log, '
                             'or all_known_logs must be provided')


async def get_log_block(session, log_url, start, end, max_retries):
    for i in range(max_retries):
        try:
            task = ct_log_api.request_from_log(session, log_url, 'get-entries',
                                               [str(start), str(end)],
                                               raise_error=True)
            response = await read_response_coro(task)
            if response is None:
                return None
            else:
                logging.info('Retrieved block {}-{} ({} kB) from {}'.format(
                    start, end, len(response) / 1000, log_url))
                return json.loads(response)['entries']
        # TODO: change this to be more specific as to what can go wrong.
        except aiohttp.ClientError as e:
            logging.error('Error while getting entries {}-{} from {} '
                          '(attempt {} of {}): {}'.format(start, end, log_url,
                                                          i + 1, max_retries,
                                                          e))
            return None
    else:
        logging.warning('Failed {} times to retrieve entries {}-{} from log '
                        '{}. Skipping.'.format(max_retries, start, end,
                                               log_url))


def process_log_block(log_url, start, block_json, log_id_dict):
    """
    Format a block of entries from the log.

    Args:
        block_json (dict):
        log_url (str):
        start (int):

    Returns:
        A string representing a block to write to output. Each line
        represents a log entry in the following form:

            Log URL, Entry Index, Timestamp, Entry Type, SHA-256 Fingerprint,
            SHA-256 Hash of Chain
    """
    lines = []
    for i, entry in enumerate(block_json):
        if log_id_dict is None:
            log = log_url
        else:
            log = str(log_id_dict[log_url])
        raw_bytes = base64.b64decode(entry['leaf_input'])
        leaf = ct_log_formats.MerkleTreeLeaf.parse(
            raw_bytes)['timestamped_entry']
        index = str(start + i)
        timestamp = str(leaf['timestamp'])
        if leaf['entry_type'] == ct_log_formats.LogEntryType.x509_entry:
            cert_bytes = leaf['signed_entry']['value']
        elif leaf['entry_type'] == ct_log_formats.LogEntryType.precert_entry:
            cert_bytes = leaf['signed_entry']['tbs_certificate']['value']
        else:
            logging.error('Unknown log entry type: {}'.format(
                leaf['entry_type']))
            cert_bytes = None
        type_int = int(leaf['entry_type'])
        if cert_bytes is None:
            continue
        cert_sha256 = hashlib.sha256()
        cert_sha256.update(cert_bytes)
        fingerprint = cert_sha256.digest().hex()
        chain_sha256 = hashlib.sha256()
        chain_sha256.update(base64.b64decode(entry['extra_data']))
        chain_hash = chain_sha256.digest().hex()
        lines.append(','.join([log, index, timestamp, str(type_int),
                               fingerprint, chain_hash]))
    return '\n'.join(lines)


async def queue_log_entries(session, download_queue, output_queue,
                            log_url, start, end, max_retries, log_id_dict):
    """

    Args:
        session:
        download_queue:
        output_queue:
        log_url:
        start:
        end:
        max_retries:

    Returns:

    """
    start_index = int(start)
    end_index = int(end)
    first_block = await get_log_block(session, log_url, start_index, end_index,
                                      max_retries)
    if first_block is None:
        logging.error('Error retrieving first block {}-{} from {}. Aborting '
                      'downloads for this log.'.format(start_index, end_index,
                                                       log_url))
        return
    line = process_log_block(log_url, start_index, first_block, log_id_dict)
    await output_queue.put(line)
    block_size = len(first_block)
    logging.info('Block size for {} is {}'.format(log_url, block_size))
    for i in range(start + block_size, end, block_size):
        await download_queue.put((log_url, i, i + block_size - 1))


async def download_entries(session, download_queue, output_queue,
                           max_retries, log_id_dict):
    """
    Continually download log blocks, and format and publish the output text.

    Args:
        session (aiohttp.ClientSession): HTTP client session to perform
            downloads with.
        download_queue (asyncio.Queue): queue from which to pull parameters
            to make requests to a log.
        output_queue (asyncio.Queue): queue on which to place the formatted
            block information.
        max_retries (int): maximum number of attempts for downloading each
            block.

    Returns:

    """
    try:
        while True:
            if download_queue.empty():
                logging.info('Download queue empty. Quitting.')
                break
            log_url, start, end = await download_queue.get()
            logging.debug('Retrieved ({}, {}, {}) from download queue'.format(
                log_url, start, end))
            block = await get_log_block(session, log_url, start, end, max_retries)
            if block is not None:
                await output_queue.put(process_log_block(log_url, start, block,
                                                         log_id_dict))
        await output_queue.put(None)
    except Exception as e:
        logging.error('Downloader error: {}'.format(e))
        await output_queue.put(None)


async def write_blocks(output_queue, out_file, num_downloads):
    """
    Write blocks from the output queue to the given file.

    Pull formatted log blocks from the queue and write it to the given file.

    Args:
        output_queue (asyncio.Queue): queue from which to pull log blocks.
        out_file (str): path to output file, or None for standard output.
        num_downloads (int): number of maximum simultaneous downloads used
            during the scrape.
        log_id_dict (dict): a map from operator
    """
    none_count = 0
    with (open(out_file, 'w') if out_file is not None else sys.stdout) as fd:
        while True:
            line = await output_queue.get()
            if line is None:
                none_count += 1
                logging.debug('Got end of one downloader (total {})'.format(
                    none_count))
                if none_count == num_downloads:
                    logging.info('All writing complete. Exiting.')
                    break
                else:
                    continue
            print(line, file=fd)
            logging.debug('Wrote {} bytes to output file'.format(len(line)))


async def queue_size_threshold(queue, size, interval=QUEUE_POLL_INTERVAL):
    """
    Wait until a queue has reached a specified size.

    Args:
        queue (asyncio.Queue): the queue to poll.
        size (int): the minimum size for the queue to reach before returning.
        interval (float): amount of time to wait in between polls.

    Returns:

    """
    while True:
        if queue.qsize() >= size:
            logging.debug('Queue size is {}. Returning.'.format(queue.qsize()))
            return
        await asyncio.sleep(interval)


async def build_log_id_dict(session, loop):
    response = await get_known_logs(loop, session, DEFAULT_LOG_LIST)
    known_logs = json.loads(response)
    log_id_map = {}
    for i, log_info in enumerate(known_logs['logs']):
        log_id_map[log_info['url']] = i
    return log_id_map


async def process(loop, args):
    # Start tasks for each log; each task tries the full set
    timeout = aiohttp.ClientTimeout(sock_connect=args.connection_timeout)
    async with aiohttp.ClientSession(loop=loop, timeout=timeout) as session:
        # Make a list of (log, start, end) tuples representing what log
        # entries to scrape.
        param_list = await build_param_list(session, loop, args.param_file,
                                            args.all_known_logs, args.log,
                                            args.start, args.end)
        logging.info('Built parameter list ({} items)'.format(len(param_list)))

        # If necessary, build a map from log URLs to operators.
        if args.log_id:
            log_id_dict = await build_log_id_dict(session, loop)
        else:
            log_id_dict = None

        # Determine the block size for each log and make a queue of download
        # parameters (log, start, end) representing blocks to download.
        download_queue = asyncio.Queue(maxsize=args.max_queue_size, loop=loop)
        output_queue = asyncio.Queue(loop=loop)
        for log_url, start, end in param_list:
            logging.debug('Creating download tasks for {} (entries {}-'
                          '{})'.format(log_url, start, end))
            # TODO: in Python 3.7 ensure_future should be create_task
            asyncio.ensure_future(queue_log_entries(session, download_queue,
                                                    output_queue, log_url,
                                                    start, end,
                                                    args.max_retries,
                                                    log_id_dict),
                                  loop=loop)

        # Make sure the queue has enough blocks before the downloaders start.
        logging.info('Waiting until download queue reaches {} '
                     'entries'.format(args.initial_queue_size))
        await queue_size_threshold(download_queue, args.initial_queue_size)
        logging.info('Download queue reached threshold level; commencing '
                     'downloads.')

        download_tasks = []
        for i in range(args.max_downloads):
            logging.debug('Scheduling downloader {} of {}'.format(
                i, args.max_downloads))
            # TODO: in Python 3.7 ensure_future should be create_task
            download_tasks.append(download_entries(session, download_queue,
                                                   output_queue,
                                                   args.max_retries,
                                                   log_id_dict))
        logging.info('Starting all downloaders.')
        output_task = write_blocks(output_queue, args.out_file,
                                   args.max_downloads)
        await asyncio.wait(download_tasks + [output_task], loop=loop)



def parse(arg_list):
    parser = argparse.ArgumentParser(parents=[common_parser.PARSER])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--param-file', help='path to file containing '
                                            'parameters for execution')
    group.add_argument('--log', help='URL of a specific log to scrape')
    group.add_argument('--all-known-logs', action='store_true',
                       help='scrape from all known logs')
    parser.add_argument('--start', help='index of log to start at')
    parser.add_argument('--end', help='index of log to end at')
    parser.add_argument('--log-id', action='store_true',
                        help='output logs by ID instead of URL')
    parser.add_argument('--max-downloads', type=int,
                        default=DEFAULT_MAX_DOWNLOADS,
                        help='maximum number of downloads to wait for at once')
    parser.add_argument('--max-retries', type=int, default=DEFAULT_MAX_RETRIES,
                        help='maximum number of times to try each block')
    parser.add_argument('--initial-queue-size',
                        type=int, default=DEFAULT_INIT_QUEUE,
                        help='number of downloads to queue before starting')
    parser.add_argument('--max-queue-size', type=int,
                        default=DEFAULT_MAX_QUEUE,
                        help='maximum number of downloads to queue at once')
    parser.add_argument('--connection-timeout',
                        type=int, default=DEFAULT_CONN_TIMEOUT,
                        help='default timeout to establish each connection')
    return parser.parse_args(arg_list)


def main(arg_list=sys.argv):
    args = parse(arg_list)
    common_parser.configure_logger(args.log_file, args.log_stream,
                                   args.log_level)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(process(loop, args))


if __name__ == '__main__':
    main()