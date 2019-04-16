"""
    Main script for starting and managing sandbox.
"""

import os
import sys
import glob
import click
import logging.config

from lisa.analysis.top_level import Master
from lisa.analysis.static_analysis import StaticAnalyzer
from lisa.analysis.network_analysis import NetworkAnalyzer
from lisa.web_api.app import app
from lisa.core.file_handling import save_output
from lisa.core.base import AnalyzedFile, AnalyzedPcap
from lisa.config import logging_config, lisa_path


logging.config.dictConfig(logging_config)
log = logging.getLogger()


@click.group()
def manage():
    """LiSa Manager - to get info about command run:
       lisa <command> --help"""


@manage.command()
@click.option('-o', '--output-file', help='Output file path.')
@click.option('-p', '--pretty', is_flag=True, help='Indented json.')
@click.argument('file', type=click.Path(exists=True))
def run_analysis(output_file, pretty, file):
    """Run full analysis."""
    # copy file to tmp folder
    data_dir = f'{lisa_path}/tmp/lala'

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    ret_val = os.system(f'cp {file} {data_dir}')

    if ret_val:
        log.critical('Error acessing folder.')
        sys.exit(1)

    # run top level and submodules
    master = Master(file, data_dir)
    master.load_analyzers()
    master.run()

    analysis_output = master.output

    # output to proper directory
    if not output_file:
        output_file = os.path.dirname(file)

    if not output_file.endswith('/'):
        output_file += '/'

    # construct output file name
    file_name = analysis_output['file_name'] + '.'
    file_name += analysis_output['analysis_start_time'] + '.json'

    output_file += file_name

    save_output(master.output, output_file, pretty)


@manage.command()
@click.option('-o', '--output-file', help='Output file path.')
@click.option('-p', '--pretty', is_flag=True, help='Indented json.')
@click.argument('file', type=click.Path(exists=True))
def static_analysis(output_file, pretty, file):
    """Run static analysis module on ELF file."""
    analyzed_file = AnalyzedFile(file)
    analyzer = StaticAnalyzer(analyzed_file)
    output = analyzer.run_analysis()

    # output to proper directory
    if not output_file:
        output_file = os.path.dirname(file)

    if not output_file.endswith('/'):
        output_file += '/'

    # construct output file name
    file_name = f'static.{os.path.basename(file)}.json'

    output_file += file_name

    save_output(output, output_file, pretty)


@manage.command()
@click.option('-o', '--output-file', help='Ouput file path.')
@click.option('-p', '--pretty', is_flag=True, help='Indented json.')
@click.option('-i', '--ip-address', help='Local IP of capturing interface.')
@click.argument('pcap_path', type=click.Path(exists=True))
def pcap_analysis(output_file, pretty, ip_address, pcap_path):
    """Run pcap analysis from networking module."""
    pcap = AnalyzedPcap(pcap_path)
    analyzer = NetworkAnalyzer(None, pcap.path, ip_address)
    analyzer.analyze_pcap()

    # output to proper directory
    if not output_file:
        output_file = os.path.dirname(pcap_path)

    if not output_file.endswith('/'):
        output_file += '/'

    # construct output file name
    file_name = f'network.{pcap.name}.json'
    output_file += file_name

    output = pcap.output
    output['network_analysis'] = analyzer.output

    save_output(output, output_file, pretty)


@manage.command()
@click.option('-p', '--pretty', is_flag=True, help='Indented jsons.')
@click.argument('folder_path', type=click.Path(exists=True))
def pcap_analysis_multi(pretty, folder_path):
    """Analyze whole folder of pcaps. Output json saved next to
    original pcap."""

    # get pcap paths
    full_path = os.path.abspath(folder_path)
    pcaps = glob.glob(f'{full_path}/**/*.pcap', recursive=True)

    number_of_pcaps = len(pcaps)
    log.info(f'Starting analysis of {number_of_pcaps} pcaps.')

    # analyze pcaps
    for i, pcap_path in enumerate(pcaps):
        log.info(f'Starting analysis of {pcap_path}.')
        log.debug('Creating analyzer.')
        pcap = AnalyzedPcap(pcap_path)
        analyzer = NetworkAnalyzer(None, pcap.path, None)

        log.debug('Calling analyze_pcap().')
        analyzer.analyze_pcap()

        # set output path
        dir_name = pcap.dir
        if not dir_name.endswith('/'):
            dir_name += '/'

        file_name = f'network.{pcap.name}.json'
        output_file = dir_name + file_name

        output = pcap.output
        output['network_analysis'] = analyzer.output
        save_output(output, output_file, pretty)

        log.info(f'Analyzed {i+1}/{number_of_pcaps} pcaps.')


@manage.command()
def serve_api():
    """Start flask server."""
    app.run(debug=True, host='0.0.0.0')


if __name__ == '__main__':
    manage()
