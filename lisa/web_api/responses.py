"""
    API responses blueprints.
"""

from lisa.config import dynamic_config


min_exectime = dynamic_config['min_exectime']
max_exectime = dynamic_config['max_exectime']


class ErrorAPIResponse():
    """Error API request response

    :param code: Error code.
    """

    def __init__(self, code):
        self._code = code
        self._message = error_messages[code]['message']

    def to_dict(self):
        return {
            'error': {
                'code': self._code,
                'message': self._message,
            }
        }


error_messages = {
    # general / resource handling
    1000: {
        'message': 'Resource not found.'
    },
    1001: {
        'message': 'Internal server error.'
    },
    1002: {
        'message': 'No existing report.'
    },
    1003: {
        'message': 'No pcap capture found.'
    },
    1004: {
        'message': 'No report found.'
    },
    1005: {
        'message': 'No machine log found.'
    },
    1006: {
        'message': 'No console output found.'
    },

    # general analysis
    2000: {
        'message': 'Parameter *pretty* must be true or false.'
    },

    # pcap analysis
    2010: {
        'message': 'Missing *pcap* parameter in the request.'
    },
    2011: {
        'message': 'Invalid pcap file name.'
    },

    # file analysis
    2020: {
        'message': 'Missing *file* parameter in the request.'
    },
    2021: {
        'message': 'Invalid file name.'
    },
    2022: {
        'message': (
            'Exectime must be positive integer between '
            f'{min_exectime} and {max_exectime}.'
        )
    },

    # management
    3000: {
        'message': 'Limit can be only positive integer.'
    }
}
