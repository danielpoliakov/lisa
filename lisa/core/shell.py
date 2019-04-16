"""
    Interactive shell.
"""

import cmd


class LisaShell(cmd.Cmd):
    """Interactive shell for QEMU IoT sandbox."""

    intro = ('Welcome to interactive shell of LiSa [Linux Sandbox].\n'
             'Type help or ? to list commands.\n')
    prompt = '(lisa) '
    file = None

    def do_start_guest(self, arg):
        """Starts guest machine."""
        pass

    def do_upload_file(self, arg):
        """Uploads file to analysis."""
        pass

    def do_determine_architecture(self, arg):
        """Sets architecture automatically."""
        pass

    def do_set_architecture(self, arg):
        """Sets architecture manually."""
        pass

    def do_full_analysis(self, arg):
        """Runs full analysis."""
        pass

    def do_sub_analysis(self, arg):
        """Runs partial analysis."""
        pass

    def do_exit(self, arg):
        """Quits shell."""
        print('Exiting.')
        return True


if __name__ == '__main__':
    LisaShell().cmdloop()
