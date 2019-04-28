"""
    Unit tests for the lisa.analysis.network_analysis module.
"""

import os
import pytest

from lisa.analysis.network_analysis import NetworkAnalyzer
from lisa.core.base import AnalyzedPcap


@pytest.fixture(scope='module')
def network():
    location = os.path.dirname(__file__)
    pcap_path = f'{location}/capture.pcap'
    pcap = AnalyzedPcap(pcap_path)
    analyzer = NetworkAnalyzer(None, pcap_path=pcap.path)
    analyzer.run_analysis()
    return analyzer.output


def test_anomalies(network):
    assert len(network['anomalies']) == 4

    anomaly_0 = {
        'name': 'blacklisted_ip_access',
        'description': (
            'Sample contacted endpoint with '
            'IP address present on blacklist.'
        ),
        'data': {
            'ip_address': '54.255.159.132'
        }
    }
    assert network['anomalies'][0] == anomaly_0

    anomaly_3 = {
        'name': 'syn_scan',
        'description': (
            'Sample send more than 100 '
            'TCP SYN packets.'
        ),
        'data': {
            'syn_count': {
                'total': 4773,
                'local': 0,
                'internet': 4773
            }
        }
    }
    assert network['anomalies'][3] == anomaly_3


def test_dns_questions(network):
    assert len(network['dns_questions']) == 1

    dns_question_0 = {
        'name': 'l.ocalhost.host',
        'type': 'A'
    }
    assert network['dns_questions'][0] == dns_question_0


def test_http_requests(network):
    assert len(network['http_requests']) == 38

    http_request_0 = {
        'method': 'POST',
        'uri': '/tmUnblock.cgi',
        'version': 'HTTP/1.1',
        'headers': {
            'Authorization': 'Basic YWRtaW46cG9ybmh1Yg==',
            'Content-Length': '215',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }
    assert network['http_requests'][0] == http_request_0

    http_request_37 = {
        'method': 'GET',
        'uri': '/hndBlock.cgi',
        'version': 'HTTP/1.1',
        'headers': {
            'Authorization': 'Basic YWRtaW46cG9ybmh1Yg==',
            'Content-Length': '215',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }
    assert network['http_requests'][37] == http_request_37


def test_port_statistics(network):
    tcp_stats = {
        '80': 4792,
        '8080': 483,
        '3003': 6
    }
    assert network['port_statistics']['TCP'] == tcp_stats

    udp_stats = {
        '53': 5
    }
    assert network['port_statistics']['UDP'] == udp_stats


def test_endpoints(network):
    assert len(network['endpoints']) == 17

    endpoint_0 = {
        'ip': '8.8.8.8',
        'ports': ['53'],
        'country': 'United States',
        'city': None,
        'asn': 15169,
        'organization': 'Google LLC',
        'blacklisted': False,
        'data_in': 98,
        'data_out': 99
    }
    assert network['endpoints'][0] == endpoint_0

    endpoint_6 = {
        'ip': '36.74.130.194',
        'ports': ['80'],
        'country': 'Indonesia',
        'city': 'Gresik',
        'asn': 7713,
        'organization': 'PT Telekomunikasi Indonesia',
        'blacklisted': False,
        'data_in': 0,
        'data_out': 629
    }
    assert network['endpoints'][6] == endpoint_6
