# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2013 YunoHost

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

"""

""" yunohost_backup.py

    Manage backups
"""
import os
import sys
import json
import yaml
import glob

from moulinette.core import MoulinetteError

def backup_init(helper=False):
    """
    Init Tahoe-LAFS configuration

    Keyword argument:
        helper -- Init as a helper node rather than a "helped" one

    """
    tahoe_cfg_dir = '/usr/share/yunohost/yunohost-config/backup'
    if helper:
        configure_cmd = '/configure_tahoe.sh helper'
    else:
        configure_cmd = '/configure_tahoe.sh'

    os.system('tahoe create-client /home/yunohost.backup/tahoe')
    os.system('/bin/bash %s%s' % (tahoe_cfg_dir, configure_cmd))
    os.system('cp %s/tahoe.cfg /home/yunohost.backup/tahoe/' % tahoe_cfg_dir)
    #os.system('update-rc.d tahoe-lafs defaults')
    #os.system('service tahoe-lafs restart')
