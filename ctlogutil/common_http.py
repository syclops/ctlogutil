"""
Convenient interface for making asynchronous HTTP requests.

Author: Steve Matsumoto <stephanos.matsumoto@sporic.me>
"""
import aiohttp
import logging


# This function is only used internally and thus is undocumented.
async def __get(session, url, params):
    return await session.get(url, params=params)


# This function is only used internally and thus is undocumented.
async def __post(session, url, data):
    return await session.post(url, data=data)


# Map strings of HTTP request types to the proper handling method.
METHOD_MAP = {
    'GET': __get,
    'POST': __post,
}
DEFAULT_METHOD = 'GET'


async def make_request(session, url, method=None, params=None,
                       raise_error=False):
    """
    Make an HTTP request and return its response.

    .. warning::

        Currently, only GET and POST are supported as request types.

    Args:
        session (aiohttp.ClientSession): the client HTTP session to use for
            connections.
        url (str): the URL to connect to.
        method (str): a string representing an HTTP request type (e.g., GET,
            POST).
        params (list): a list of parameter-value pairs.
        raise_error (bool): raise an exception if the response code is a
            client error.

    Returns:
        An aiohttp.ClientResponse object representing the response to the
        request.
    """
    if method is None:
        method = DEFAULT_METHOD
    if params is None:
        params = {}
    try:
        resp = await METHOD_MAP[method](session, url, params)
        logging.debug('Received response {} from {}'.format(resp.status, url))
        resp.raise_for_status()
        return resp
    except aiohttp.ClientError as e:
        logging.error('Client error: {}'.format(e))
        if raise_error:
            raise e
        else:
            return None


async def read_response(resp):
    """
    Get response text from a future representing a request.

    Args:
        resp (aiohttp.ClientResponse): the response to read text from.

    Returns:
        A str object representing the response text or None if the response
        was null.
    """
    if resp is None:
        return None
    return await resp.read()


async def read_response_coro(coro):
    return await read_response(await coro)
