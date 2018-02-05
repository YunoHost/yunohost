import glob
import os
import requests
import base64
import time
import json
import errno

from moulinette import m18n
from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger
from yunohost.tools import Migration

logger = getActionLogger('yunohost.migration')


class MyMigration(Migration):
    "Upgrade the system to Debian Stretch and Yunohost 3.0"

    def backward(self):
        # Not possible because that's a non-reversible operation ?
        pass

    def migrate(self):

        self.check_assertions()

        pass


    def check_assertions(self):

        # Be on jessie

        # Have > 1 Go free space on /var/ ?

        pass

    @property
    def disclaimer(self):

        # Backup ?

        # Problematic apps ? E.g. not official or community+working ?

        # Manually modified files ? (c.f. yunohost service regen-conf)

        return "Hurr durr itz dungerus"
