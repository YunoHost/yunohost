import os
import pytest

import moulinette
from moulinette import m18n, Moulinette
from yunohost.utils.error import YunohostError
from contextlib import contextmanager


@pytest.fixture(scope="session", autouse=True)
def clone_test_app(request):
    cwd = os.path.split(os.path.realpath(__file__))[0]

    if not os.path.exists(cwd + "/apps"):
        os.system("git clone https://github.com/YunoHost/test_apps %s/apps" % cwd)
    else:
        os.system("cd %s/apps && git pull > /dev/null 2>&1" % cwd)


def get_test_apps_dir():
    cwd = os.path.split(os.path.realpath(__file__))[0]
    return os.path.join(cwd, "apps")


@contextmanager
def message(mocker, key, **kwargs):
    mocker.spy(m18n, "n")
    yield
    m18n.n.assert_any_call(key, **kwargs)


@contextmanager
def raiseYunohostError(mocker, key, **kwargs):
    with pytest.raises(YunohostError) as e_info:
        yield
    assert e_info._excinfo[1].key == key
    if kwargs:
        assert e_info._excinfo[1].kwargs == kwargs


def pytest_addoption(parser):
    parser.addoption("--yunodebug", action="store_true", default=False)


#
# Tweak translator to raise exceptions if string keys are not defined       #
#


old_translate = moulinette.core.Translator.translate


def new_translate(self, key, *args, **kwargs):

    if key not in self._translations[self.default_locale].keys():
        raise KeyError("Unable to retrieve key %s for default locale !" % key)

    return old_translate(self, key, *args, **kwargs)


moulinette.core.Translator.translate = new_translate


def new_m18nn(self, key, *args, **kwargs):
    return self._namespaces[self._current_namespace].translate(key, *args, **kwargs)


moulinette.core.Moulinette18n.n = new_m18nn

#
# Init the moulinette to have the cli loggers stuff                         #
#


def pytest_cmdline_main(config):

    import sys

    sys.path.insert(0, "/usr/lib/moulinette/")
    import yunohost

    yunohost.init(debug=config.option.yunodebug)

    class DummyInterface:

        type = "cli"

        def prompt(self, *args, **kwargs):
            raise NotImplementedError

        def display(self, message, *args, **kwargs):
            print(message)

    Moulinette._interface = DummyInterface()
