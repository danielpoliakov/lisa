"""
    Module trying to update binaries to bypass
    ptrace(PTRACE_TRACEME, 0, 0, 1) anti-debugging technique.
"""

import r2pipe
import logging.config

from lisa.config import logging_config

logging.config.dictConfig(logging_config)
log = logging.getLogger()


def find_n_replace_ptrace_calls(file_path):
    """Analyzes binary, finds ptrace syscall and replaces
    all ptrace syscalls with instruction `add v0, zero, zero`.

    :param file_path: Path to binary file.
    """
    r2 = r2pipe.open(file_path)

    # analyze all
    r2.cmd('aa')

    # get syscalls
    syscalls = r2.cmdj('/cj syscall')

    ptrace_calls = []

    for syscall in syscalls:
        # lookup previous instruction
        instr_before = r2.cmdj('pdj -1 @' + str(syscall['offset']))[0]
        instr_args = instr_before['disasm'].split()

        # skip unsupported instrcutions
        if instr_args[0] != 'addiu':
            continue

        # found ptrace call
        if instr_args[3] == '0xfba':
            ptrace_calls.append(syscall['offset'])

    num_calls = len(ptrace_calls)
    log.info(f'AADM: {num_calls} ptrace syscall(s) found.')

    # reopen w/ write permission
    r2.cmd('oo+')

    # lists offsets
    for offset in ptrace_calls:
        # replace syscall
        r2.cmd(f'wa add v0, zero, zero @ {offset}')

        # check effect
        new_op = r2.cmdj(f'pdj 1 @ {offset}')[0]['opcode']
        if new_op != 'syscall':
            log.info(f'AADM: Syscall @ {offset} successfully '
                     f'replaced by {new_op}.')
        else:
            log.warning(f'AADM: Syscall @ {offset} could not be replaced.')

    r2.quit()
