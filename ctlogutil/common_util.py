import functools
import operator

def filter_none(values):
    return list(filter(functools.partial(operator.is_not, None), values))