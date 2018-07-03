"""
Common output methods for ctlogutil.

Author: Steve Matsumoto <stephanos.matsumoto@sporic.me>
"""
import json
import pandas as pd


# Default output settings.
DEFAULT_OUTPUT_FORMAT = 'json'
DEFAULT_JSON_INDENT = 2


def write_json(fd, data, indent=DEFAULT_JSON_INDENT):
    """
    Write a JSON dictionary (with formatting) to a file.

    Args:
        fd (io.textIOWrapper): a file object to write the dict to.
        data (dict): the JSON object representing the log list.
        indent (int): the number of spaces to indent keys.
    """
    print(json.dumps(data, indent=indent), file=fd)


def write_csv(fd, data):
    """
    Write the log list to a file in CSV format.

    Args:
        fd (io.textIOWrapper): a file object to write the dict to.
        data (dict): the JSON object representing the log list.
    """
    # df = pd.DataFrame.from_dict(data)
    df = pd.io.json.json_normalize(data)
    print(df.to_csv(index=False), file=fd)


# Register output handlers here.
OUTPUT_HANDLERS = {
    'json': write_json,
    'csv': write_csv,
}

