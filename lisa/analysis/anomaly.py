"""
    Representing anomalies in modules output.
"""


class Anomaly():
    """Anomaly base structure.

    :param name: Name of anomaly.
    :param description: Short description.
    :param data: Data of occurance.
    """

    def __init__(self, name, description, data):
        self._name = name
        self._description = description
        self._data = data

    def to_dict(self):
        return {
            'name': self._name,
            'description': self._description,
            'data': self._data
        }
