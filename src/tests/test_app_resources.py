import os
import pytest

from yunohost.utils.resources import AppResource, AppResourceManager, AppResourceClassesByType

dummyfile = "/tmp/dummyappresource-testapp"


class DummyAppResource(AppResource):

    type = "dummy"

    default_properties = {
        "file": "/tmp/dummyappresource-__APP__",
        "content": "foo",
    }

    def provision_or_update(self, context):

        open(self.file, "w").write(self.content)

        if self.content == "forbiddenvalue":
            raise Exception("Emeged you used the forbidden value!1!£&")

    def deprovision(self, context):

        os.system(f"rm -f {self.file}")


AppResourceClassesByType["dummy"] = DummyAppResource


def setup_function(function):

    clean()


def teardown_function(function):

    clean()


def clean():

    os.system(f"rm -f {dummyfile}")


def test_provision_dummy():

    current = {"resources": {}}
    wanted = {"resources": {"dummy": {}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=False)
    assert open(dummyfile).read().strip() == "foo"


def test_deprovision_dummy():

    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=False)
    assert not os.path.exists(dummyfile)


def test_provision_dummy_nondefaultvalue():

    current = {"resources": {}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    assert not os.path.exists(dummyfile)
    AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=False)
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy():

    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "bar"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=False)
    assert open(dummyfile).read().strip() == "bar"


def test_update_dummy_fail():

    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "forbiddenvalue"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    with pytest.raises(Exception):
        AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=False)
    assert open(dummyfile).read().strip() == "forbiddenvalue"


def test_update_dummy_failwithrollback():

    current = {"resources": {"dummy": {}}}
    wanted = {"resources": {"dummy": {"content": "forbiddenvalue"}}}

    open(dummyfile, "w").write("foo")

    assert open(dummyfile).read().strip() == "foo"
    with pytest.raises(Exception):
        AppResourceManager("testapp", current=current, wanted=wanted).apply(rollback_if_failure=True)
    assert open(dummyfile).read().strip() == "foo"
