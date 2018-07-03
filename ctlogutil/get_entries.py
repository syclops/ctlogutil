"""Get entries from a CT log.
"""
import argparse


def parse(arg_list):
    parser = argparse.ArgumentParser()
    parser.add_argument('log_url', help='HTTPS URL of log')
    parser.add_argument('command', help='API endpoint to call')
    parser.add_argument('params', nargs=argparse.REMAINDER,
                        help='Arguments to log command')


def handle(arg_list):
    args = parse(arg_list)
