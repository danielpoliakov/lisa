"""
    Unit tests for lisa.analysis.anomaly module.
"""

from lisa.analysis.anomaly import Anomaly


def test_anomaly_empty():
    anomaly = Anomaly(None, None, None)

    assert anomaly.to_dict() == {
        'name': None,
        'description': None,
        'data': None
    }


def test_anomaly_standard():
    anomaly = Anomaly(
        'test_anomaly',
        'Test description.',
        {'anomaly_data': 42}
    )

    assert anomaly.to_dict() == {
        'name': 'test_anomaly',
        'description': 'Test description.',
        'data': {'anomaly_data': 42}
    }


def test_anomaly_nested():
    anomaly = Anomaly(
        'nested_anomaly',
        'Random description.',
        {
            'anomaly_data': {
                'nested_anomaly_data': {
                    'ip_address': '192.168.0.1'
                }
            }
        }
    )

    assert anomaly.to_dict() == {
        'name': 'nested_anomaly',
        'description': 'Random description.',
        'data': {
            'anomaly_data': {
                'nested_anomaly_data': {
                    'ip_address': '192.168.0.1'
                }
            }
        }
    }
