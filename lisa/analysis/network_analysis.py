"""
    Network analysis module.
"""

import os
import ipaddress
import collections
import geoip2.database
import logging.config
import disspcap

from lisa.core.base import AbstractSubAnalyzer
from lisa.analysis.anomaly import Anomaly
from lisa.config import lisa_path, logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


with open(f'{lisa_path}/data/ipblacklist') as f:
    ipblacklist = []
    for line in f:
        iprange = line.rstrip('\n').split('-')
        iprange = (int(ipaddress.ip_address(iprange[0])),
                   int(ipaddress.ip_address(iprange[1])))
        ipblacklist.append(iprange)


def is_ip_blacklisted(ipaddr):
    """Binary searches whether ip address is in a
    blacklist (reported malicious ip).

    :param ipaddr: String IP address.
    :returns: True x False.
    """
    ip = int(ipaddress.ip_address(ipaddr))
    low = 0
    high = len(ipblacklist) - 1

    while low <= high:
        mid = low + (high - low) // 2
        ipmid = ipblacklist[mid]

        if ip >= ipmid[0] and ip <= ipmid[1]:
            return True
        elif ip < ipmid[0]:
            high = mid - 1
        elif ip > ipmid[1]:
            low = mid + 1

    return False


def is_ip_local(ipaddr):
    """Returns True if ip address is in local range.

    :param ipaddr: String IP address.
    :returns: True x False.
    """
    ip = int(ipaddress.ip_address(ipaddr))

    # 10.x.x.x
    if ip >= 167772160 and ip < 184549376:
        return True

    # 172.16.0.0 – 172.31.255.255
    if ip >= 2886729728 and ip < 2887778304:
        return True

    # 192.168.x.x
    if ip >= 3232235520 and ip < 3232301056:
        return True

    return False


class NetworkAnalyzer(AbstractSubAnalyzer):
    """Provides networking analysis.

    :param file: AnalyzedFile's object.
    :param pcap_path: Path of pre-captured pcap.
    :param ip_address: Local IP of capturing interface.
    """

    def __init__(self, file, pcap_path=None, ip_address=None):
        super().__init__(file)
        self._anomalies = []
        self._syn_count = 0
        self._fin_count = 0
        self._syn_count_local = 0
        self._fin_count_local = 0
        self._endpoints = []
        self._dns_questions = set()
        self._irc_messages = []
        self._http_requests = []
        self._telnet_data = []
        self._port_statistics = {
            'TCP': collections.Counter(),
            'UDP': collections.Counter()
        }

        # set up maxmind geoip2 databases
        self._maxmind = False

        city = f'{lisa_path}/data/geolite2databases/GeoLite2-City.mmdb'
        asn = f'{lisa_path}/data/geolite2databases/GeoLite2-ASN.mmdb'

        if os.path.isfile(city) and os.path.isfile(asn):
            self._reader_city = geoip2.database.Reader(city)
            self._reader_asn = geoip2.database.Reader(asn)
            self._maxmind = True

        if pcap_path:
            self._pcap_path = os.path.abspath(pcap_path)
        else:
            self._pcap_path = f'{self._file.data_dir}/capture.pcap'

        self._local_ip = None

        if file is not None:
            self._local_ip = '10.0.2.15'

    @property
    def pcap_path(self):
        """Path of analyzed pcap."""
        return self._pcap_path

    @pcap_path.setter
    def pcap_path(self, pcap_path):
        """Path of analyzed pcap."""
        self._pcap_path = pcap_path

    def run_analysis(self):
        """Main analysis method.

        :returns: Dictionary containing analysis results.
        """
        log.debug('NetworkAnalyzer started.')

        # pcap analysis
        self.analyze_pcap()

        log.debug('NetworkAnalyzer finished.')

        return self._output

    def _analyze_endpoint(self, ip):
        """Returns information about endpoint (IP address)

        :param ip: String representation of IP address.
        :param port: Port number.
        :returns: Dictionary with endpoint information.
        """
        if self._maxmind:
            # get maxmind geolite2 info
            try:
                rc = self._reader_city.city(ip)
                ra = self._reader_asn.asn(ip)
                endpoint = {
                    'ip': ip,
                    'ports': [],
                    'country': rc.country.name,
                    'city': rc.city.name,
                    'asn': ra.autonomous_system_number,
                    'organization': ra.autonomous_system_organization,
                    'blacklisted': is_ip_blacklisted(ip),
                    'data_in': 0,
                    'data_out': 0
                }
            except geoip2.errors.AddressNotFoundError as e:
                endpoint = {
                    'ip': ip,
                    'ports': [],
                    'blacklisted': is_ip_blacklisted(ip),
                    'data_in': 0,
                    'data_out': 0
                }
        else:
            endpoint = {
                'ip': ip,
                'ports': [],
                'blacklisted': is_ip_blacklisted(ip),
                'data_in': 0,
                'data_out': 0
            }

        # report anomaly
        if endpoint['blacklisted']:
            name = 'blacklisted_ip_access'
            description = ('Sample contacted endpoint with IP '
                           'address present on blacklist.')
            data = {
                'ip_address': ip
            }

            anomaly = Anomaly(name, description, data)
            self._anomalies.append(anomaly.to_dict())

        return endpoint

    def _l7_analysis(self, packet):
        """Analyzes application level of pcap.

        :param packet: Single packet.
        """
        if packet.dns:
            if packet.dns.qr == 0:
                # dns question
                for question in packet.dns.questions:
                    self._dns_questions.add(question)

            # report anomaly
            if (
                packet.dns.question_count > 499
                or packet.dns.answer_count > 499
                or packet.dns.authority_count > 499
                or packet.dns.additional_count > 499
            ):
                name = 'dns_header_many_records'
                description = ('Sample sends DNS header with either big '
                               'number of questions, answers, authorities '
                               'or additionals.')
                data = {
                    'question_count': packet.dns.question_count,
                    'answer_count': packet.dns.answer_count,
                    'authority_count': packet.dns.authority_count,
                    'additional_count': packet.dns.additional_count
                }

                anomaly = Anomaly(name, description, data)
                self._anomalies.append(anomaly.to_dict())

        if packet.http:
            if packet.http.is_request:
                # http request
                request = {
                    'method': packet.http.request_method,
                    'uri': packet.http.request_uri,
                    'version': packet.http.version,
                    'headers': {}
                }
                # headers
                for key in packet.http.headers:
                    request['headers'][key] = packet.http.headers[key]

                self._http_requests.append(request)

        if packet.irc:
            for message in packet.irc.messages:
                # irc messages
                str_message = message.command
                for param in message.params:
                    str_message += ' ' + param
                str_message += ' ' + message.trailing
                str_message = str_message.strip()
                if str_message != '':
                    self._irc_messages.append(str_message)

        if packet.telnet:
            if len(packet.telnet.data.strip()) != 0:
                self._telnet_data.append(packet.telnet.data)

    def analyze_pcap(self):
        """Analyzes captured pcap file. Fills self._endpoints,
        self._port_statistics, self._syn_count, self._fin_count and others.
        """

        endpoints = {}

        if self._local_ip is None:
            self._local_ip = disspcap.most_common_ip(self._pcap_path)

        pcap = disspcap.Pcap(self._pcap_path)

        while True:

            packet = pcap.next_packet()
            if packet is None:
                break

            if packet.ipv4:
                packet_ip = packet.ipv4
            elif packet.ipv6:
                packet_ip = packet.ipv6
            else:
                continue

            # TCP communication
            if packet.tcp:

                if packet_ip.source == self._local_ip:
                    # outgoing packet
                    ip = packet_ip.destination
                    port = str(packet.tcp.destination_port)
                    length = packet.tcp.payload_length

                    if packet.tcp.syn:
                        # search for syn scan
                        self._syn_count += 1
                        if is_ip_local(ip):
                            self._syn_count_local += 1
                    elif packet.tcp.fin and not packet.tcp.ack:
                        # search for fin scan
                        self._fin_count += 1
                        if is_ip_local(ip):
                            self._fin_count_local += 1

                    if length != 0:
                        # analyze endpoint
                        if ip not in endpoints:
                            endpoint = self._analyze_endpoint(ip)
                            endpoints[ip] = endpoint

                        endpoints[ip]['data_out'] += length

                        if port not in endpoints[ip]['ports']:
                            endpoints[ip]['ports'].append(port)

                    self._port_statistics['TCP'][port] += 1

                else:
                    # incomming packet
                    ip = packet_ip.source
                    port = str(packet.tcp.source_port)
                    length = packet.tcp.payload_length

                    if length != 0:
                        if ip not in endpoints:
                            endpoint = self._analyze_endpoint(ip)
                            endpoints[ip] = endpoint

                        endpoints[ip]['data_in'] += length

                        if port not in endpoints[ip]['ports']:
                            endpoints[ip]['ports'].append(port)

                    self._port_statistics['TCP'][port] += 1

            # UDP communication
            if packet.udp:

                if packet_ip.source == self._local_ip:
                    # outgoing packet
                    ip = packet_ip.destination
                    port = str(packet.udp.destination_port)
                    length = packet.udp.payload_length

                    if length != 0:
                        # analyze endpoints
                        if ip not in endpoints:
                            endpoint = self._analyze_endpoint(ip)
                            endpoints[ip] = endpoint

                        endpoints[ip]['data_out'] += length

                        if port not in endpoints[ip]['ports']:
                            endpoints[ip]['ports'].append(port)

                    self._port_statistics['UDP'][port] += 1
                else:
                    # incommming packet
                    ip = packet_ip.source
                    port = str(packet.udp.source_port)
                    length = packet.udp.payload_length

                    if length != 0:
                        # analyze endpoint
                        if ip not in endpoints:
                            endpoint = self._analyze_endpoint(ip)
                            endpoints[ip] = endpoint

                        endpoints[ip]['data_in'] += length

                        if port not in endpoints[ip]['ports']:
                            endpoints[ip]['ports'].append(port)

                    self._port_statistics['UDP'][port] += 1

            self._l7_analysis(packet)

        self._endpoints = list(endpoints.values())

        # report anomaly
        if self._syn_count > 100:
            name = 'syn_scan'
            description = 'Sample send more than 100 TCP SYN packets.'
            data = {
                'syn_count': {
                    'total': self._syn_count,
                    'local': self._syn_count_local,
                    'internet': self._syn_count - self._syn_count_local
                }
            }

            anomaly = Anomaly(name, description, data)
            self._anomalies.append(anomaly.to_dict())

        # report anomaly
        if self._fin_count > 100:
            name = 'fin_scan'
            description = 'Sample send more than 100 TCP FIN packets.'
            data = {
                'fin_count': {
                    'total': self._fin_count,
                    'local': self._fin_count_local,
                    'internet': self._fin_count - self._fin_count_local
                }
            }

            anomaly = Anomaly(name, description, data)
            self._anomalies.append(anomaly.to_dict())

        # save pcap analysis output
        self._output['anomalies'] = self._anomalies

        self._output['irc_messages'] = self._irc_messages

        self._output['dns_questions'] = []

        # question structure
        for question in self._dns_questions:
            qname, qtype = question.split()
            self._output['dns_questions'].append(
                {
                    'name': qname,
                    'type': qtype
                }
            )

        self._output['http_requests'] = self._http_requests

        self._output['telnet_data'] = self._telnet_data

        most_common_tcp = self._port_statistics['TCP'].most_common()
        most_common_udp = self._port_statistics['UDP'].most_common()

        ports_tcp_count = len(most_common_tcp)
        ports_udp_count = len(most_common_udp)

        # report anomaly
        if ports_tcp_count + ports_udp_count > 100:
            name = 'port_scan'
            description = 'Sample communicated on more than 100 ports.'
            data = {
                'tcp_ports_count': ports_tcp_count,
                'udp_ports_count': ports_udp_count
            }

            anomaly = Anomaly(name, description, data)
            self._anomalies.append(anomaly.to_dict())

        self._output['port_statistics'] = {
            'TCP': collections.OrderedDict(most_common_tcp),
            'UDP': collections.OrderedDict(most_common_udp)
        }

        self._output['endpoints'] = self._endpoints
