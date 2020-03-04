"""
    QEMU guest manipulation utils.
"""

import os
import time
import shutil
import pexpect
import logging

from lisa.config import logging_config, images

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class QEMUGuest():
    """QEMU guest handling.

    :param file: Targeted binary to emulate.
    """

    count = 0

    def __init__(self, file):
        self._arch = file.arch
        self._bit = int(file.bit)
        self._endian = file.endian
        self._file_name = file.name
        self._file = file
        self._is_running = False
        self._proc = None
        self._fs = None

        if self._arch not in images:
            log.critical(
                'Image for target architecture not present in config.'
            )
            return

        # fork image
        base_fs = images[self._arch]['rootfs']
        self._fs = f'{self._file.data_dir}/rootfs'
        shutil.copy(base_fs, self._fs)

        # copy elf binary to image
        log.info(f'Copying {file.name} to rootfs.')
        os.system(
            'e2cp -G 0 -O 0 -P 755 '
            f'{file.path} {self._fs}:/root/analyzed_bin'
        )

        run = images[self._arch]['run']
        self._run_cmd = f'{run} {self._file.data_dir}/rootfs'
        self._prompt = images[self._arch]['prompt']

        QEMUGuest.count += 1

    @property
    def is_running(self):
        """Guest is running - boolean."""
        return self._is_running

    @property
    def process(self):
        """Pexpect spawned process."""
        return self._proc

    def send_command(self, command):
        """Sends command to guest VM and returns it's output.

        :param command: String containing desired commmand.
        :returns: Command's output inside VM.
        """
        if not self._is_running:
            return None

        self._proc.sendline(command)
        self._proc.expect(self._prompt)
        return self._proc.before

    def start_vm(self, disable_ipv6=True):
        """Starts guest VM.

        :param: Disable IPv6 on eth0.
        """

        log.info(
            f'Requested: {self._arch}, {self._bit}-bit, {self._endian} endian.'
        )

        self._proc = pexpect.spawn(
            self._run_cmd, encoding='utf-8', timeout=self._file.exec_time+50
        )
        self._proc.logfile = open(
            f'{self._file.data_dir}/machine.log', 'w', encoding='utf-8'
        )

        # login
        self._proc.expect('login: ')
        self._proc.sendline('root')
        self._proc.expect('[pP]assword: ')
        self._proc.sendline('root')
        self._proc.expect(self._prompt)

        self._is_running = True

        if disable_ipv6:
            self.send_command(
                'echo 1 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6'
            )

    def run_and_analyze(self, exec_time, capture_pcap=True):
        """Runs targeted binary and monitors through
        Systemtap .ko module.

        :param exec_time: Time of execution.
        :param capture_pcap: Run tcpdump and capture pcap.
        """
        log.debug('Starting analysis module and target binary.')

        self.send_command('tcpdump -i eth0 -w /stap/capture.pcap &')

        time.sleep(1)

        command = (
            f'staprun -c /stap/lisa.sh '
            '/stap/lisa.ko > /stap/behav.out &'
        )
        self.send_command(command)

        # execution time
        time.sleep(3 + exec_time)

    def poweroff_vm(self):
        """Shutdowns guest VM."""
        self._proc.sendline('sync')
        self._proc.expect(self._prompt)
        self._proc.sendline('poweroff')
        self._proc.expect(pexpect.EOF)
        self._proc.logfile.close()
        self._is_running = False

    def extract_output(self, keep_fs=False):
        """Extracts behav.out, prog.log, capture.pcap from filesystem.

        :param keep_fs: Do not delete target filesystem snapshotted
                        during analysis.
        """
        extract_behav = (
            'e2cp '
            f'{self._fs}:/stap/behav.out '
            f'{self._file.data_dir}/'
        )
        os.system(extract_behav)

        extract_progout = (
            'e2cp '
            f'{self._fs}:/stap/prog.log '
            f'{self._file.data_dir}/'
        )
        os.system(extract_progout)

        extract_pcap = (
            'e2cp '
            f'{self._fs}:/stap/capture.pcap '
            f'{self._file.data_dir}/'
        )
        os.system(extract_pcap)

        log.debug('Behavioral info (behav.out) saved in data directory.')

        if not keep_fs:
            os.system(f'rm {self._fs}')

    def get_ip(self):
        """Returns local IP address of VM."""
        command = 'ifconfig eth0 | awk \'/inet addr/ '
        command += '{gsub("addr:", "", $2); print $2}\''
        self._proc.sendline(command)
        self._proc.expect('10.0.2.*\r\n')
        return self._proc.after.strip()
