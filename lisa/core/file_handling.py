"""
    File handling module extending default os module
    with custom functionality.
"""

import json
import logging.config

from contextlib import contextmanager
from lisa.config import logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


@contextmanager
def opened_w_error(filename, mode="r"):
    """Context manager based on https://www.python.org/dev/peps/pep-0343/"""
    try:
        f = open(filename, mode)
    except EnvironmentError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()


def save_output(output, output_file, indented=False):
    """Saves analysis output as json to output_path.

    :param output: Analysis output to be saved.
    :param output_file: Output file path.
    :param indented: Indentation of json file.
    :returns: Boolean whether file was saved succesfully.
    """
    with opened_w_error(output_file, 'w') as (f, err):
        if err:
            log.critical(str(err))
            log.critical(f'Output could not be saved in {output_file}.')
        else:
            if indented:
                json.dump(output, f, indent=4)
            else:
                json.dump(output, f)
            log.info(f'File saved succesfully to {output_file}.')
