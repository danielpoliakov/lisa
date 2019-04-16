"""
    Top level of analysis - containing master analyzer and handles
    sub-analyzers modules.
"""

import logging.config

from importlib import import_module
from datetime import datetime
from lisa.core.base import AnalyzedFile
from lisa.config import analyzers_config
from lisa.config import logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


def create_analyzer(analyzer_path, file_path):
    """Imports analyzer class and creates analyzer object

    :param analyzer_path: Path to analyzer in format 'module.Class'.
    :returns: Instantiated analyzer object.
    """
    mod_name, class_name = analyzer_path.rsplit('.', 1)

    analyzer_module = import_module(mod_name)
    analyzer_class = getattr(analyzer_module, class_name)

    return analyzer_class(file_path)


class Master():
    """Top level analyzer of binary files.

    :param file_path: Path to binary file.
    :param data: Path to directory for analysis files.
    :param exec_time: Execution time for behavioral modules.
    """

    def __init__(self, file_path, data, exec_time=20):
        self._file = AnalyzedFile(file_path, data, exec_time)
        self._analyzers = []

    @property
    def output(self):
        """Full analysis output."""
        return self.file.output

    @property
    def file(self):
        """Analyzed file."""
        return self._file

    def load_analyzers(self):
        """Loader of sub-analyzers."""
        for analyzer_path in analyzers_config:
            analyzer = create_analyzer(analyzer_path, self._file)
            self._analyzers.append(analyzer)

    def run(self):
        """Top level run function."""
        log.info('Starting full analysis.')

        # metadata
        self._file.output['analysis_start_time'] = datetime.now().strftime(
            '%Y-%m-%dT%H:%M')

        for analyzer in self._analyzers:
            sub_output = analyzer.run_analysis()
            _, analysis_name = analyzer.__module__.rsplit('.', 1)
            self._file.output[analysis_name] = sub_output
