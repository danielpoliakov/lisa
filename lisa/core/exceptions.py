"""
    LiSa exceptions.
"""


class CallException(Exception):
    """Raised when subprocess fails. Catches output with
    fail information.

    :param output: Output of subprocess.
    """

    def __init__(self, output):
        self.output = output
