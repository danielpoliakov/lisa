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
