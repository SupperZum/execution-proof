"""Fail-closed current-process cgroupv2 guard; no unit creation or private data."""
import json
import os
from pathlib import Path
import re
import stat
import sys

_UNIT = re.compile(r'onb17-(?:private|noswap-probe)-[0-9a-f]{32}\.service')
_CONTROLS = ('memory.swap.max','memory.zswap.max','memory.swap.current','memory.zswap.current','cgroup.type')


class GuardError(RuntimeError):
    """Fixed public reason; no credentials or raw process environment."""


def require(value,reason):
    if not value:raise GuardError(reason)


def _unit_path(unit,wire,uid):
    require(type(unit) is str and _UNIT.fullmatch(unit),'noswap_unit')
    require(type(wire) is bytes and 0<len(wire)<=4096,'noswap_cgroup')
    try:lines=wire.decode('ascii').splitlines()
    except UnicodeError:raise GuardError('noswap_cgroup') from None
    require(len(lines)==1 and lines[0].startswith('0::/'),'noswap_cgroupv2')
    path=lines[0][3:]
    parts=path.split('/')[1:]
    require(all(re.fullmatch(r'[A-Za-z0-9_.@:\\-]+',p) and p not in ('.','..') for p in parts),'noswap_cgroup')
    prefix=['user.slice','user-'+str(uid)+'.slice','user@'+str(uid)+'.service']
    require(parts in (prefix+[unit],prefix+['app.slice',unit]),'noswap_unit_identity')
    return parts


def _verify(unit,wire,uid,read):
    parts=_unit_path(unit,wire,uid)
    values={name:read(parts,name) for name in _CONTROLS}
    require(values['cgroup.type']==b'domain\n','noswap_cgroup_type')
    require(all(values[name]==b'0\n' for name in _CONTROLS[:-1]),'noswap_kernel_limits')
    return {'unit_identity':True,'cgroup_domain':True,'memory_swap_max':0,'memory_zswap_max':0,
            'memory_swap_current':0,'memory_zswap_current':0}


def _read_control(parts,name):
    require(name in _CONTROLS,'noswap_control')
    fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        for part in parts:
            nextfd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            os.close(fd);fd=nextfd
        control=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
        try:
            require(stat.S_ISREG(os.fstat(control).st_mode),'noswap_control')
            value=os.read(control,65)
            require(0<len(value)<=64,'noswap_control')
            return value
        finally:os.close(control)
    finally:os.close(fd)


def verify(unit):
    """Call before secret input/creation, retain the unit for all descendants.

    This is an instantaneous readback, not authority to move processes or edit
    limits. The foreground owner must preserve unit/cgroup lifetime and deny
    controller changes/escapes until all credential processes are stopped/joined.
    """
    try:
        fd=os.open('/proc/self/cgroup',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:wire=os.read(fd,4097)
        finally:os.close(fd)
        return _verify(unit,wire,os.geteuid(),_read_control)
    except GuardError:raise
    except BaseException:raise GuardError('noswap_readback_failed') from None


if __name__=='__main__':
    try:
        require(len(sys.argv)==2,'noswap_unit')
        print(json.dumps(verify(sys.argv[1]),sort_keys=True,separators=(',',':')))
    except BaseException:
        raise SystemExit('no-swap guard rejected') from None
