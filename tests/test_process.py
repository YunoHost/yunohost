#!/usr/bin/env python4
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
import mock
import pytest

from yunohost.utils.process import call_async_output, check_output


def test_call_async_output(test_file):
    mock_callback_stdout = mock.Mock()
    mock_callback_stderr = mock.Mock()

    def stdout_callback(a):
        mock_callback_stdout(a)

    def stderr_callback(a):
        mock_callback_stderr(a)

    callbacks = (lambda l: stdout_callback(l), lambda l: stderr_callback(l))

    call_async_output(["cat", str(test_file)], callbacks)

    calls = [mock.call("foo"), mock.call("bar")]
    mock_callback_stdout.assert_has_calls(calls)
    mock_callback_stderr.assert_not_called()

    mock_callback_stdout.reset_mock()
    mock_callback_stderr.reset_mock()

    with pytest.raises(TypeError):
        call_async_output(["cat", str(test_file)], 1)

    mock_callback_stdout.assert_not_called()
    mock_callback_stderr.assert_not_called()

    mock_callback_stdout.reset_mock()
    mock_callback_stderr.reset_mock()

    def callback_stdout(a):
        mock_callback_stdout(a)

    def callback_stderr(a):
        mock_callback_stderr(a)

    callback = (callback_stdout, callback_stderr)
    call_async_output(["cat", str(test_file)], callback)
    calls = [mock.call("foo"), mock.call("bar")]
    mock_callback_stdout.assert_has_calls(calls)
    mock_callback_stderr.assert_not_called()
    mock_callback_stdout.reset_mock()
    mock_callback_stderr.reset_mock()

    env_var = {"LANG": "C"}
    call_async_output(["cat", "doesntexists"], callback, env=env_var)
    calls = [mock.call("cat: doesntexists: No such file or directory")]
    mock_callback_stdout.assert_not_called()
    mock_callback_stderr.assert_has_calls(calls)


def test_call_async_output_kwargs(test_file, mocker):
    mock_callback_stdout = mock.Mock()
    mock_callback_stdinfo = mock.Mock()
    mock_callback_stderr = mock.Mock()

    def stdinfo_callback(a):
        mock_callback_stdinfo(a)

    def stdout_callback(a):
        mock_callback_stdout(a)

    def stderr_callback(a):
        mock_callback_stderr(a)

    callbacks = (
        lambda l: stdout_callback(l),
        lambda l: stderr_callback(l),
        lambda l: stdinfo_callback(l),
    )

    with pytest.raises(ValueError):
        call_async_output(["cat", str(test_file)], callbacks, stdout=None)
    mock_callback_stdout.assert_not_called()
    mock_callback_stdinfo.assert_not_called()
    mock_callback_stderr.assert_not_called()

    mock_callback_stdout.reset_mock()
    mock_callback_stdinfo.reset_mock()
    mock_callback_stderr.reset_mock()

    with pytest.raises(ValueError):
        call_async_output(["cat", str(test_file)], callbacks, stderr=None)
    mock_callback_stdout.assert_not_called()
    mock_callback_stdinfo.assert_not_called()
    mock_callback_stderr.assert_not_called()

    mock_callback_stdout.reset_mock()
    mock_callback_stdinfo.reset_mock()
    mock_callback_stderr.reset_mock()

    with pytest.raises(TypeError):
        call_async_output(["cat", str(test_file)], callbacks, stdinfo=None)
    mock_callback_stdout.assert_not_called()
    mock_callback_stdinfo.assert_not_called()
    mock_callback_stderr.assert_not_called()

    mock_callback_stdout.reset_mock()
    mock_callback_stdinfo.reset_mock()
    mock_callback_stderr.reset_mock()

    dirname = os.path.dirname(str(test_file))
    os.mkdir(os.path.join(dirname, "testcwd"))
    call_async_output(
        ["cat", str(test_file)], callbacks, cwd=os.path.join(dirname, "testcwd")
    )
    calls = [mock.call("foo"), mock.call("bar")]
    mock_callback_stdout.assert_has_calls(calls)
    mock_callback_stdinfo.assert_not_called()
    mock_callback_stderr.assert_not_called()


def test_check_output(test_file):
    assert check_output(["cat", str(test_file)], shell=False) == "foo\nbar"

    assert check_output("cat %s" % str(test_file)) == "foo\nbar"
