# Copyright 2026 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Confinement for a process that handles data the service does not trust
(a tenant's installation media).

Such a process runs as the service user, which can read everything the
service can. confine() is called in the child before it executes the
worker and takes away what the worker has no use for, with what the kernel
offers and without needing privileges:

- namespaces of its own (user, network, IPC, mount): no network, none of
  the service's sockets in /run (the brokers of the tenants, the API)
- Landlock: only the files it is told about can be opened, for reading
  (the interpreter and its libraries, the media) or for writing (where the
  media is unpacked); no TCP, no signals to the service's processes
- resource limits: CPU time, memory, the size of a file, no core file

Each of these is applied if the host allows it; applied() tells which of
them a host provides. The resource limits alone do not keep a worker from
the service's data, so whether untrusted data is handled at all on a host
is a matter of policy (see refusal()): not unless the namespaces or
Landlock apply, by default.
"""

import ctypes
import os
import resource
import sys

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWNET = 0x40000000
MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REC, MS_PRIVATE = 2, 4, 8, 0x4000, 1 << 18
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24
PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4
# the same numbers on every architecture Linux has had Landlock on
SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
FS_EXECUTE, FS_WRITE_FILE, FS_READ_FILE, FS_READ_DIR = 1, 2, 4, 8
FS_REMOVE_DIR, FS_REMOVE_FILE, FS_MAKE_DIR, FS_MAKE_REG, FS_MAKE_SYM = 16, 32, 128, 256, 4096
FS_REFER, FS_TRUNCATE = 1 << 13, 1 << 14
FS_V1 = (1 << 13) - 1
FS_OF_A_FILE = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE
FS_READ = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR
FS_WRITE = (FS_READ | FS_WRITE_FILE | FS_REMOVE_DIR | FS_REMOVE_FILE | FS_MAKE_DIR |
            FS_MAKE_REG | FS_MAKE_SYM | FS_REFER | FS_TRUNCATE)

# where the service's sockets are: nothing of it for a worker
HIDDEN = ('/run/confluent', '/var/run/confluent')
# what any program of the system needs to start
SYSTEM = ('/usr', '/lib', '/lib64', '/lib32', '/bin', '/sbin', '/etc/ld.so.cache',
          '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/localtime',
          '/dev/zero', '/dev/urandom', '/opt/confluent/lib', '/opt/confluent/bin')
# (what discards output is written to)
DEVICES = ('/dev/null',)

CPU_SECONDS = 4 * 3600
MEMORY = 4 * 2 ** 30
FILE_SIZE = 64 * 2 ** 30


class _RulesetAttr(ctypes.Structure):
    _fields_ = [('handled_access_fs', ctypes.c_uint64),
                ('handled_access_net', ctypes.c_uint64),
                ('scoped', ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def interpreter_paths():
    """What the interpreter running this needs to read to run again."""
    paths = set([sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix,
                 os.path.dirname(os.path.realpath(sys.executable)),
                 os.path.dirname(os.path.dirname(os.path.realpath(__file__)))])
    for entry in sys.path + os.environ.get('PYTHONPATH', '').split(os.pathsep):
        if entry:
            paths.add(os.path.realpath(entry))
    return sorted(path for path in paths if path and path != '/')


def landlock_abi():
    """The version of Landlock the kernel has (0: none)."""
    try:
        version = _libc().syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0,
                                  LANDLOCK_CREATE_RULESET_VERSION)
    except Exception:
        return 0
    return version if version > 0 else 0


def _namespaces():
    """Leave the service's network, IPC and view of /run behind."""
    libc = _libc()
    uid, gid = os.getuid(), os.getgid()
    flags = CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWNS
    if uid != 0:
        flags |= CLONE_NEWUSER
    if libc.unshare(flags) != 0:
        return False
    if uid != 0:
        # (the same user as before, as files are concerned)
        with open('/proc/self/setgroups', 'w') as out:
            out.write('deny')
        with open('/proc/self/gid_map', 'w') as out:
            out.write('{0} {0} 1'.format(gid))
        with open('/proc/self/uid_map', 'w') as out:
            out.write('{0} {0} 1'.format(uid))
    if libc.mount(None, b'/', None, MS_REC | MS_PRIVATE, None) != 0:
        return False
    for path in HIDDEN:
        if os.path.isdir(path) and not os.path.islink(path):
            if libc.mount(b'tmpfs', path.encode(), b'tmpfs',
                          MS_NOSUID | MS_NODEV | MS_NOEXEC, b'size=64k,mode=000') != 0:
                return False
    return True


def _landlock(read, write):
    """Only these trees and files from now on."""
    abi = landlock_abi()
    if not abi:
        return False
    libc = _libc()
    handled = FS_V1
    if abi >= 2:
        handled |= FS_REFER
    if abi >= 3:
        handled |= FS_TRUNCATE
    attr = _RulesetAttr(handled, 0, 0)
    size = 8
    if abi >= 4:
        attr.handled_access_net, size = 3, 16  # no TCP: neither bind nor connect
    if abi >= 6:
        attr.scoped, size = 3, 24  # no abstract sockets or signals beyond itself
    ruleset = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), size, 0)
    if ruleset < 0:
        return False
    try:
        for paths, access in ((read, FS_READ), (write, FS_WRITE),
                              (DEVICES, FS_READ_FILE | FS_WRITE_FILE)):
            for path in paths:
                try:
                    fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
                except OSError:
                    continue  # (not on this system)
                try:
                    allowed = access & handled
                    if not os.path.isdir(path):
                        allowed &= FS_OF_A_FILE
                    rule = _PathBeneathAttr(allowed, fd)
                    if libc.syscall(SYS_LANDLOCK_ADD_RULE, ruleset, LANDLOCK_RULE_PATH_BENEATH,
                                    ctypes.byref(rule), 0) != 0:
                        return False
                finally:
                    os.close(fd)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            return False
        return libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset, 0) == 0
    finally:
        os.close(ruleset)


def _limits():
    resource.setrlimit(resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY, MEMORY))
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_SIZE, FILE_SIZE))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def confine(read=(), write=(), report=None, use=('namespaces', 'landlock')):
    """Confine this process (see the module). Called between fork and
    exec, as the preexec_fn of the worker.

    read and write name the files and trees the worker may open, beyond
    what any program needs to start; report, if given, is a file
    descriptor that is told what was applied. use names what to try:
    leaving namespaces cannot be undone halfway, so a worker only tries
    what supported() found to work here.
    """
    os.setsid()
    os.umask(0o022)
    applied = ['limits']
    _limits()
    if 'namespaces' in use:
        try:
            if _namespaces():
                applied.append('namespaces')
        except Exception:
            pass
    if 'landlock' in use:
        try:
            if _landlock(tuple(SYSTEM) + tuple(read) + tuple(write), tuple(write)):
                applied.append('landlock')
        except Exception:
            pass
    _drop_privileges()
    if report is not None:
        os.write(report, ','.join(applied).encode())
    return applied


def _drop_privileges():
    # The service is started with capabilities (to bind low ports, to
    # send raw packets) that a program it runs would inherit: not this one.
    try:
        libc = _libc()
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
        for capability in range(64):
            # (for a service running as root, which gets back at exec
            # whatever is left in this set)
            libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)
    except Exception:
        pass


def confiner(read=(), write=()):
    """A preexec_fn that confines a worker running this interpreter."""
    read = tuple(interpreter_paths()) + tuple(read)
    write = tuple(write)
    use = supported()

    def preexec():
        confine(read, write, use=use)
    preexec.read, preexec.write, preexec.use = read, write, use
    return preexec


_supported = []


def supported():
    """What of confine() works on this host (found out once)."""
    if not _supported:
        _supported.append(tuple(applied()))
    return _supported[0]


def applied(read=(), write=(), user=None):
    """What confine() manages to apply on this host, found out in a
    process made for it: a list of 'limits', 'namespaces', 'landlock'.

    user, (uid, gid), is who to find it out for when that is not who
    asks (root asking on behalf of the service user).
    """
    receive, send = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(receive)
            if user is not None:
                os.setgroups([])
                os.setgid(user[1])
                os.setuid(user[0])
            confine(read, write, report=send)
        finally:
            os._exit(0)
    os.close(send)
    try:
        with os.fdopen(receive, 'rb') as result:
            told = result.read().decode()
    finally:
        os.waitpid(pid, 0)
    return [part for part in told.split(',') if part]


# ------------------------------------------------- what a host lacks, and why

LAYERS = ('limits', 'namespaces', 'landlock')
SYSCTL_FILE = '/etc/sysctl.d/90-confluent-sandbox.conf'
APPARMOR_PROFILE = '/etc/apparmor.d/confluent'
APPARMOR_SOURCES = ('/opt/confluent/share/apparmor/confluent',
                    os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                                 'apparmor', 'confluent'))
SETUP_HINT = 'confluent-netns sandbox --enable'


def _setting(path):
    try:
        with open(path) as setting:
            return setting.read().strip()
    except OSError:
        return None


def diagnose(found):
    """Why a layer of the confinement is missing on this host, and what
    would provide it: a list of {'layer', 'reason', 'fix'} (and 'sysctl',
    the settings that would, or 'apparmor': True, where a profile for the
    service would), empty when found has them all."""
    problems = []
    if 'namespaces' not in found:
        problem = {'layer': 'namespaces'}
        if _setting('/proc/sys/user/max_user_namespaces') == '0':
            problem.update(reason='user namespaces are turned off (user.max_user_namespaces = 0)',
                           sysctl={'user.max_user_namespaces': '15000'}, fix=SETUP_HINT)
        elif _setting('/proc/sys/kernel/unprivileged_userns_clone') == '0':
            problem.update(
                reason='unprivileged user namespaces are turned off '
                       '(kernel.unprivileged_userns_clone = 0)',
                sysctl={'kernel.unprivileged_userns_clone': '1'}, fix=SETUP_HINT)
        elif _setting('/proc/sys/kernel/apparmor_restrict_unprivileged_userns') == '1':
            problem.update(
                reason='AppArmor restricts user namespaces to programs with a profile '
                       'that allows them',
                apparmor=True, fix=SETUP_HINT + ', then restart confluent')
        else:
            problem.update(reason='namespaces could not be created (in a container, '
                                  'or refused by a security policy of the host)',
                           fix='allow the service user to create user namespaces')
        problems.append(problem)
    if 'landlock' not in found:
        problem = {'layer': 'landlock'}
        active = _setting('/sys/kernel/security/lsm')
        if landlock_abi():
            problem.update(reason='Landlock is available but could not be applied',
                           fix='see the trace log of the service')
        elif active is not None and 'landlock' not in active.split(','):
            problem.update(
                reason='Landlock is not among the active security modules ({0})'.format(active),
                fix='boot with lsm={0},landlock on the kernel command line (Linux 5.13 '
                    'or later, built with Landlock)'.format(active))
        else:
            problem.update(reason='the kernel does not provide Landlock',
                           fix='needs Linux 5.13 or later, built with Landlock')
        problems.append(problem)
    return problems


def policy():
    """What a tenant's media is handled with ([tenants] media_sandbox in
    service.cfg):

    'required'  only where Landlock applies
    'default'   only where Landlock or the namespaces apply (not set)
    'none'      also with the resource limits alone: the worker can then
                read what the service can, for a host that provides
                neither and an operator who accepts that
    """
    try:
        import confluent.config.conf as conf
        configured = (conf.get_option('tenants', 'media_sandbox') or '').strip().lower()
    except Exception:
        configured = ''
    return configured if configured in ('required', 'none') else 'default'


def required():
    """Whether a tenant's media is only handled where Landlock applies."""
    return policy() == 'required'


def refusal(found=None):
    """Why a tenant's media is not handled on this host, or None if it is."""
    found = supported() if found is None else found
    chosen = policy()
    if chosen == 'none':
        return None
    if chosen == 'required' and 'landlock' not in found:
        return ('this server cannot confine the programs that read it with Landlock, '
                'which is required here')
    if 'landlock' not in found and 'namespaces' not in found:
        return 'this server cannot confine the programs that read it'
    return None


def missing():
    """The layers this host does not provide to the workers."""
    return [layer for layer in LAYERS if layer not in supported()]


def enable(problems, run=None, out=None):
    """Provide what diagnose() found missing, as far as settings of the
    host can (run as root, on the operator's request): returns the lines
    telling what was done and what is left to do."""
    import shutil
    import subprocess
    run = run or subprocess.call
    told = []
    settings = {}
    for problem in problems:
        settings.update(problem.get('sysctl', {}))
    if settings:
        with open(SYSCTL_FILE, 'w') as conffile:
            conffile.write('# Written by "confluent-netns sandbox --enable": lets the confluent\n'
                           '# service confine the programs that read the media of tenants.\n')
            for name in sorted(settings):
                conffile.write('{0} = {1}\n'.format(name, settings[name]))
        run(['sysctl', '-q', '-p', SYSCTL_FILE])
        told.append('wrote {0} ({1})'.format(SYSCTL_FILE, ', '.join(
            '{0} = {1}'.format(name, settings[name]) for name in sorted(settings))))
    if any(problem.get('apparmor') for problem in problems):
        source = [path for path in APPARMOR_SOURCES if os.path.exists(path)]
        if not source:
            told.append('the AppArmor profile of the service is not installed')
        else:
            shutil.copyfile(source[0], APPARMOR_PROFILE)
            if run(['apparmor_parser', '-r', APPARMOR_PROFILE]) == 0:
                told.append('installed and loaded {0}; restart confluent for it to '
                            'apply'.format(APPARMOR_PROFILE))
            else:
                told.append('installed {0}, which AppArmor did not load'.format(APPARMOR_PROFILE))
    for problem in problems:
        if not problem.get('sysctl') and not problem.get('apparmor'):
            told.append('{0}: {1}; {2}'.format(problem['layer'], problem['reason'], problem['fix']))
    return told
