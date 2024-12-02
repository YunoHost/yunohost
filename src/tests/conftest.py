#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

import os
from contextlib import contextmanager
from unittest.mock import Mock

import moulinette
import pytest
from moulinette import Moulinette, m18n

from yunohost.utils.error import YunohostError


@pytest.fixture(scope="session", autouse=True)
def clone_test_app(request):
    cwd = os.path.split(os.path.realpath(__file__))[0]

    if not os.path.exists(cwd + "/apps"):
        os.system(
            f"git clone https://github.com/YunoHost/test_apps {cwd}/apps --depth 1"
        )
    else:
        os.system("cd %s/apps && git pull > /dev/null 2>&1" % cwd)


def get_test_apps_dir():
    cwd = os.path.split(os.path.realpath(__file__))[0]
    return os.path.join(cwd, "apps")


@contextmanager
def message(key, **kwargs):
    m = Mock(wraps=m18n.n)
    old_m18n = m18n.n
    m18n.n = m
    yield
    try:
        m.assert_any_call(key, **kwargs)
    finally:
        m18n.n = old_m18n


@contextmanager
def raiseYunohostError(mocker, key, **kwargs):
    with pytest.raises(YunohostError) as e_info:
        yield
    assert e_info._excinfo[1].key == key
    if kwargs:
        assert e_info._excinfo[1].kwargs == kwargs


#
# Tweak translator to raise exceptions if string keys are not defined       #
#


old_translate = moulinette.core.Translator.translate


def new_translate(self, key, *args, **kwargs):
    if key not in self._translations[self.default_locale].keys():
        raise KeyError("Unable to retrieve key %s for default locale !" % key)

    return old_translate(self, key, *args, **kwargs)


moulinette.core.Translator.translate = new_translate


#
# Init the moulinette to have the cli loggers stuff                         #
#


def pytest_cmdline_main(config):
    import sys
    from pathlib import Path

    # Tweak python path such that "import yunohost" imports "this" code and not the one from /usr/lib/python3/dist-packages
    code_root = str(Path(__file__).parent.parent.parent)
    sys.path.insert(0, code_root)

    import yunohost

    yunohost.init()

    class DummyInterface:
        type = "cli"

        def prompt(self, *args, **kwargs):
            raise NotImplementedError

        def display(self, message, *args, **kwargs):
            print(message)

    Moulinette._interface = DummyInterface()
