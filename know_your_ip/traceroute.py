#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import shlex
from subprocess import Popen, PIPE


def os_traceroute(ip, max_hops=30):
    if os.name == 'nt':
        cmd = 'tracert -h {0} -d {1}'.format(max_hops, ip)
    elif os.name == 'posix':
        cmd = 'traceroute -m {0} -n {1} '.format(max_hops, ip)
    else:
        # FIXME: other OSes.
        cmd = 'traceroute {0}'.format(ip)

    p = Popen(shlex.split(cmd), stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()

    return out
