"""Command handlers for CT log utility.

This module simply imports the modules that implement the tools provided by
ctlogutil and provides a simple interface (in the form of a generic handler
dispatcher) for dispatching commands to the appropriate tool.

New tools can be added to ctlogutil in this module by importing the appropriate
module and defining the mapping from the tool to its handler.
"""
# Local imports
import ct_log_api
import list_logs
import scrape_logs


# Define tools here as a mapping from the tool name to its handler. Typically,
# the handler is simply the imported module's main function.
HANDLERS = {
    'list': list_logs.main,
    'api': ct_log_api.main,
    'scrape': scrape_logs.main
}


def handle(command, args):
    """Run a command and its arguments with the appropriate function.

    Arguments:
        command (str): the name of the command to run.
        args (list): the arguments to pass to the handling function.

    Returns:
        The return value of the handling function.
    """
    HANDLERS[command](args)
