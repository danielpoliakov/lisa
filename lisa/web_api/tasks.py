"""
    Celery tasks.
"""

import os
import logging.config

from celery import states, Task
from lisa.analysis.top_level import Master
from lisa.analysis.network_analysis import NetworkAnalyzer
from lisa.core.file_handling import save_output
from lisa.core.base import AnalyzedPcap
from lisa.web_api.app import celery_app
from lisa.config import logging_config, storage_path

logging.config.dictConfig(logging_config)
log = logging.getLogger()


class LiSaBaseTask(Task):

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        self.update_state(
            state=states.FAILURE,
            meta={
                'exc_type': type(exc).__name__,
                'traceback': einfo.traceback,
                'filename': os.path.basename(args[0])
            }
        )
        self.traceback = einfo.traceback

    def on_success(self, retval, task_id, args, kwargs):
        self.update_state(
            state=states.SUCCESS,
            meta={
                'filename': os.path.basename(args[0])
            }
        )


@celery_app.task(bind=True, base=LiSaBaseTask)
def pcap_analysis(self, pcap_path, pretty=False):
    """Pcap analysis task.

    :param pcap_path: Path to pcap.
    :param pretty: Output json indentation.
    """
    self.update_state(meta={'filename': os.path.basename(pcap_path)})

    pcap = AnalyzedPcap(pcap_path)
    analyzer = NetworkAnalyzer(None, pcap.path, None)
    analyzer.analyze_pcap()

    output_file = f'{storage_path}/{self.request.id}/report.json'

    output = pcap.output
    output['network_analysis'] = analyzer.output

    save_output(output, output_file, pretty)

    return 'pcap'


@celery_app.task(bind=True, base=LiSaBaseTask)
def full_analysis(self, file_path, pretty=False, exec_time=20):
    """Full sandbox analysis task.

    :param file_path: Path to file.
    :param pretty: Output json indentation.
    :param exec_time: Execution time.
    """
    self.update_state(meta={'filename': os.path.basename(file_path)})

    data_dir = f'{storage_path}/{self.request.id}'

    # run top level and submodules
    master = Master(file_path, data_dir, exec_time)
    master.load_analyzers()
    master.run()

    output_file = f'{data_dir}/report.json'

    save_output(master.output, output_file, pretty)

    return 'binary'
