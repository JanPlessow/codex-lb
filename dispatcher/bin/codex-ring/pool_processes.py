"""Kernel process identities for supervised native descendants on macOS.

Read process metadata only, never argv or environment. Darwin retains the
creation parent's unique identity after ordinary reparenting/setsid; PID reuse
cannot make an unrelated process a member of a known job. Unobserved chains of
short-lived double-fork intermediates still require a registered tool launcher.
"""
import ctypes
import errno
import os
import signal
import subprocess
import sys
import time


class UniqueInfo(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_char * 16), ('unique', ctypes.c_uint64),
                ('parent', ctypes.c_uint64), ('version', ctypes.c_int32),
                ('original_parent_version', ctypes.c_int32),
                ('reserved2', ctypes.c_uint64), ('reserved3', ctypes.c_uint64)]


def identity(pid):
    if sys.platform != 'darwin':
        raise OSError('this pool process tracker requires macOS')
    lib = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    info = UniqueInfo()
    count = lib.proc_pidinfo(pid, 17, 0, ctypes.byref(info), ctypes.sizeof(info))
    if count != ctypes.sizeof(info):
        error = ctypes.get_errno()
        if error == errno.ESRCH:
            return None
        raise OSError(error, 'cannot inspect process identity')
    return info.unique, info.parent


def process_table():
    result = subprocess.run(['/bin/ps', '-axo', 'pid=,uid=,stat='],
                            capture_output=True, text=True, timeout=5, check=True)
    table = {}
    for line in result.stdout.splitlines():
        pid, uid, state = line.split()
        if int(uid) != os.getuid() or state.startswith('Z'):
            continue
        info = identity(int(pid))
        if info is not None:
            table[int(pid)] = info
    return table


def descendants(table, known):
    result = set(known)
    while True:
        expanded = result | {unique for unique, parent in table.values() if parent in result}
        if expanded == result:
            return result
        result = expanded


def settle(known):
    """Kill surviving registered descendants; false means do not declare idle."""
    try:
        owned = set(known)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            table = process_table()
            owned |= descendants(table, owned)
            targets = {pid: unique for pid, (unique, _) in table.items()
                       if unique in owned and pid != os.getpid()}
            if not targets:
                return True
            for pid, unique in targets.items():
                current = identity(pid)
                if current is not None and current[0] == unique:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            time.sleep(.05)
        return False
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
