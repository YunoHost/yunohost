#!/usr/bin/env python3

import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from types import NoneType
from typing import Generator

import pytest

TEST_DIRS = {
    "2": Path(__file__).parent / "test_helpers.v2.d",
    "2.1": Path(__file__).parent / "test_helpers.v2.1.d",
}


def list_tests() -> list[tuple[str, str]]:
    tests: list[tuple[str, str]] = []
    for helpers_version, test_dir in TEST_DIRS.items():
        for file in test_dir.glob("ynhtest_*.sh"):
            file_testname = file.name.removeprefix("ynhtest_").removesuffix(".sh")

            result = subprocess.check_output(
                ["bash", "-c", f"source {file}; declare -F"]
            )
            for line in result.decode("utf-8").splitlines():
                if match := re.match(r"^declare -f ynhtest_(.*)$", line):
                    testfn = match.group(1)
                    tests.append((helpers_version, file_testname, testfn))

    return tests


@pytest.fixture(scope="module")
def http_server() -> Generator[HTTPServer, None, None]:
    tempdir = tempfile.mkdtemp()

    class Handler(SimpleHTTPRequestHandler):
        directory = tempdir

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=self.directory, **kwargs)

    class Server(HTTPServer):
        def run(self):
            try:
                self.serve_forever()
            except KeyboardInterrupt:
                print("Closing HTTP server on keybord request...")
            finally:
                self.server_close()

    host = "127.0.0.1"
    port = 1312
    server = Server((host, port), Handler)
    thread = threading.Thread(None, server.run)
    thread.start()
    yield server
    server.shutdown()
    thread.join()
    shutil.rmtree(tempdir)


@pytest.fixture(scope="module")
def var_www_tempdir() -> Generator[Path, None, None]:
    tempdir = Path(tempfile.mkdtemp())
    var_www = tempdir / "var" / "www"
    var_www.mkdir(parents=True)
    tempdir.chmod(stat.S_IROTH | stat.S_IXOTH)
    yield tempdir
    shutil.rmtree(tempdir)


@pytest.fixture(scope="module")
def ynhtest_app() -> Generator[Path, None, None]:
    app_dir = Path("/etc/yunohost/apps/ynhtest")
    app_dir.mkdir(parents=True)
    settings_file = app_dir / "settings.yml"
    settings_file.write_text("id: ynhtest\n")
    yield app_dir
    shutil.rmtree(app_dir)


@pytest.fixture(scope="module")
def ensure_user() -> None:
    if subprocess.run(
        ["getent", "passwd", "ynhtest"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode:
        subprocess.run(["useradd", "--system", "ynhtest"])


@pytest.mark.parametrize("version,file,func", list_tests())
def test_helpers(
    version: str,
    file: str,
    func: str,
    var_www_tempdir: Path,
    http_server: HTTPServer,
    ensure_user: NoneType,
) -> None:
    wrapper_file = Path(__file__).parent / "test_helpers_wrapper.sh"
    test_file = TEST_DIRS[version] / f"ynhtest_{file}.sh"
    test_func = f"ynhtest_{func}"

    test_env = os.environ | {
        "HTTPSERVER_DIR": str(http_server.RequestHandlerClass.directory),
        "HTTPSERVER_PORT": str(http_server.server_port),
        "VAR_WWW": str(var_www_tempdir),
    }

    subprocess.check_call(
        [wrapper_file, version, test_file, test_func],
        env=test_env,
        stderr=subprocess.STDOUT,
    )
