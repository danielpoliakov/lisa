import yara


class YaraScan:
    # https://yara.readthedocs.io/en/stable/yarapython.html
    def __init__(self, path):
        """
        param path: absolute path to rules
        """
        is_compiled = self.is_compiled_rules(path)
        if not is_compiled:
            # Load rules from file and compile
            self.rules = yara.compile(filepath=path)
        else:
            # Load compiled rules to memory
            self.rules = yara.load(path)
        self.__rule_matched = ""

    def is_compiled_rules(self, path):
        """
        Check if uploaded yara rule is compiled rule or string
        param path: absolute path to rules
        """
        yara_file_magic = b"YARA"
        with open(path, "rb") as read_header:
            if read_header.read(4) == yara_file_magic:
                return True
        # FIXME if reading the file returns error?
        return False

    def scan_callback(self, data):
        if data["matches"]:
            print(data)  # TODO use logging instead
            self.__rule_matched = data
            return yara.CALLBACK_ABORT
        return yara.CALLBACK_CONTINUE

    def scan_file(self, file_path):
        self.rules.match(filepath=file_path, callback=self.scan_callback)

    def scan_process(self, pid):
        self.rules.match(pid=pid, callback=self.scan_callback)

    def get_scan_result(self):
        """
        Allow other classes to get the scan result
        Clean the result after it was called
        Remove data to avoid wrong result in cache
        """
        result = self.__rule_matched
        self.__rule_matched = ""
        return result
