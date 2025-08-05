#!/usr/bin/env python3
#
# Copyright (c) 2025 YunoHost Contributors
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

# mypy: disallow_untyped_defs

import os
import random
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from pydantic import BaseModel
from logging import getLogger
from typing import Any, Callable, Dict, List, Union, Literal, Iterator, TYPE_CHECKING

from moulinette import m18n
from .file_utils import chmod, chown, mkdir, rm
from .process import check_output
from .misc import random_ascii

from .error import YunohostError, YunohostValidationError, YunohostPackagingError
from .system import system_arch

if TYPE_CHECKING:
    from ..log import OperationLogger

logger = getLogger("yunohost.utils.resources")

SOURCES_CACHE_DIR = "/var/tmp/yunohost/download/"


def evaluate_if_clause(if_clause: str, env: dict[str, Any]) -> bool:
    from .eval import evaluate_simple_js_expression
    from ..app import _hydrate_app_template
    if_clause_hydrated = _hydrate_app_template(if_clause, env, raise_exception_if_missing_var=True)
    try:
        return evaluate_simple_js_expression(if_clause_hydrated, env)
    except KeyError as e:
        logger.error(f"Failed to interpret if clause « {if_clause} »")
        if re.search(r"[A-Z0-9]__\s*[=!]+\s*['\"]\w", if_clause):
            logger.error("Beware that when comparing __FOO__ to a string, __FOO__ should itself be wrapped in quotes")
        raise e


AppResourceTodo = \
    tuple[Literal["provision"], tuple[str, str], None, "AppResource"] | \
    tuple[Literal["update"], tuple[str, str], "AppResource", "AppResource"] | \
    tuple[Literal["deprovision"], tuple[str, str], "AppResource", None]


class AppResourceManager:

    def __init__(self, app: str, current: Dict, wanted: Dict, env: dict[str, Any]):
        self.app = app
        self.current = current
        self.wanted = wanted
        self.env = env

        if "resources" not in self.current:
            self.current["resources"] = {}
        if "resources" not in self.wanted:
            self.wanted["resources"] = {}

        self.todos = self.compute_todos(env)

    def compute_todos(self, env: dict[str, Any]) -> dict[str, list["AppResourceTodo"]]:

        current = {(r.type, r.id): r for r in self.load_resources(self.current, env)}
        wanted = {(r.type, r.id): r for r in self.load_resources(self.wanted, env)}

        todos_by_type: dict[str, list["AppResourceTodo"]] = {}

        for type_and_id, res in reversed(current.items()):
            type_, id_ = type_and_id
            if type_and_id not in wanted.keys():
                if type_ not in todos_by_type:
                    todos_by_type[type_] = []
                todos_by_type[type_].append(("deprovision", type_and_id, res, None))

        for type_and_id, res in wanted.items():
            type_, id_ = type_and_id
            if type_ not in todos_by_type:
                todos_by_type[type_] = []
            if type_and_id not in current.keys():
                todos_by_type[type_].append(("provision", type_and_id, None, res))
            else:
                todos_by_type[type_].append(("update", type_and_id, current[type_and_id], res))

        return todos_by_type

    def apply(
        self,
        rollback_and_raise_exception_if_failure: bool,
        operation_logger: Union["OperationLogger", None] = None
    ) -> None:

        completed: dict[str, list] = {type_: [] for type_ in self.todos.keys()}
        rollback = False
        exception = None

        for type_, todos in self.todos.items():
            for todo, name, old, new in todos:
                try:
                    if todo == "deprovision":
                        # FIXME : i18n, better info strings
                        logger.info(f"Deprovisioning {name}...")
                        assert old
                        old.deprovision()
                    elif todo == "provision":
                        logger.info(f"Provisioning {name}...")
                        assert new
                        new.provision_or_update()
                    elif todo == "update":
                        logger.info(f"Updating {name}...")
                        assert new
                        new.provision_or_update()
                except (KeyboardInterrupt, Exception) as e:
                    exception = e
                    if isinstance(e, KeyboardInterrupt):
                        logger.error(m18n.n("operation_interrupted"))
                    else:
                        logger.warning(f"Failed to {todo} {name} : {e}")
                    if rollback_and_raise_exception_if_failure:
                        rollback = True
                        completed[type_].append((todo, name, old, new))
                        break
                    else:
                        # We actually want to continue if rollback_and_raise_exception_if_failure is False
                        # for example in the context of a remove script, we want to cleanup as much as possible
                        # even if for some reason some stuff may fail to get cleaned up
                        pass
                else:
                    completed[type_].append((todo, name, old, new))

            if rollback:
                break

            if hasattr(AppResourceClassesByType[type_], "grouped_trigger_after_apply"):
                completed_for_this_type = [(old if todo == "deprovision" else new) for todo, _, old, new in completed[type_]]
                try:
                    AppResourceClassesByType[type_].grouped_trigger_after_apply(completed_for_this_type)
                except (KeyboardInterrupt, Exception) as e:
                    logger.warning(f"Failed to propagate changes related to {type_} : {e}")
                    if rollback_and_raise_exception_if_failure:
                        rollback = True
                        break

        if rollback:
            rollbacked: dict[str, list["AppResourceTodo"]] = {type_: [] for type_ in completed.keys()}
            for type_, completed_for_this_type in completed.items():
                for todo, name, old, new in completed_for_this_type:
                    try:
                        # (NB. here we want to undo the todo)
                        if todo == "deprovision":
                            # FIXME : i18n, better info strings
                            logger.info(f"Reprovisioning {name}...")
                            assert old
                            old.provision_or_update()
                        elif todo == "provision":
                            logger.info(f"Deprovisioning {name}...")
                            assert new
                            new.deprovision()
                        elif todo == "update":
                            logger.info(f"Reverting {name}...")
                            assert old
                            old.provision_or_update()
                    except (KeyboardInterrupt, Exception) as e:
                        if isinstance(e, KeyboardInterrupt):
                            logger.error(m18n.n("operation_interrupted"))
                        else:
                            logger.error(f"Failed to rollback {name} : {e}")
                    else:
                        rollbacked[type_].append((todo, name, old, new))

                if hasattr(AppResourceClassesByType[type_], "grouped_trigger_after_apply"):
                    rollbacked_for_this_type = [(new if todo == "provision" else old) for todo, _, old, new in rollbacked[type_]]
                    try:
                        AppResourceClassesByType[type_].grouped_trigger_after_apply(rollbacked_for_this_type)
                    except (KeyboardInterrupt, Exception) as e:
                        logger.warning(f"Failed to propagate changes related to {type_}'s rollback : {e}")
                        if rollback_and_raise_exception_if_failure:
                            rollback = True
                            break

        if exception:
            if rollback_and_raise_exception_if_failure:
                logger.error(
                    m18n.n("app_resource_failed", app=self.app, error=exception)
                )
                if operation_logger:
                    failure_message_with_debug_instructions = operation_logger.error(
                        str(exception)
                    )
                    raise YunohostError(
                        failure_message_with_debug_instructions, raw_msg=True
                    )
                else:
                    raise YunohostError(str(exception), raw_msg=True)
            else:
                logger.error(exception)

    def load_resources(self, manifest: dict[str, dict[str, Any]], env: dict[str, Any]) -> Iterator["AppResource"]:

        resources: dict[str, dict[str, Any]] = manifest["resources"]
        # NB: the "manifest" may actually be basically empty for cases like install
        # where the current state is empty
        packaging_format = float(manifest.get("packaging_format", 0))  # type: ignore[arg-type]

        for type_, res_properties in resources.items():

            res_properties = res_properties.copy()
            if type_ not in AppResourceClassesByType:
                raise YunohostPackagingError(f"Unknown resource type {type_}")

            ResourceClass = AppResourceClassesByType[type_]

            # Handle compabitibility with packaging v2 because some properties names changes since then
            if packaging_format < 3 and hasattr(ResourceClass, "convert_packaging_v2_props"):
                ResourceClass.convert_packaging_v2_props(res_properties)

            multi = ResourceClass.__fields__["multi"].default
            if not multi:
                res_properties = {"main": res_properties}
            else:
                # Make sure we have a "main" property and that it's first in the list
                res_properties = {"main": res_properties.pop("main", {}), **res_properties}

            # Iterate on other confs than "main"
            for key, values in res_properties.items():

                if not isinstance(values, dict):
                    raise YunohostPackagingError(
                        f"Uhoh, in {type_} resource properties, {key} should be associated with a dict ... (did you meant <res_id>.{key} ?)"
                    )

                if_clause = values.pop("if") if "if" in values else None
                if if_clause is not None and not evaluate_if_clause(if_clause, self.env):
                    logger.debug(f"Skipping resource {type_}.{key} because 'if' clause is not met")
                    continue
                logger.debug(f"Loading resource {type_}.{key}")
                ResourceClass.validate_properties_from_package(**values)
                yield ResourceClass(
                    **values,
                    id=key,
                    env=env,
                    type=type_,
                    app=self.app,
                )


class AppResource(BaseModel):

    id: str
    app: str
    type: str
    workdir: str | None = None
    multi: bool = False
    exposed_properties: list[str]
    helpers_version: float = 0

    @classmethod
    def validate_properties_from_package(cls, **props) -> None:  # type: ignore[no-untyped-def]

        exposed_properties = cls.__fields__["exposed_properties"].default
        incorrect_properties = [k for k in props.keys() if k not in exposed_properties]
        if incorrect_properties:
            cls_type = cls.__fields__["type"].default
            raise YunohostPackagingError(f"Uhoh, the following properties are unknown / not exposed for {cls_type}-type resources: {', '.join(incorrect_properties)}")

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        env = kwargs.pop("env")

        super().__init__(**kwargs)

        self.helpers_version = float(env["YNH_HELPERS_VERSION"])
        self.workdir = env.get("YNH_APP_BASEDIR")
        self.hydrate_properties(env=env)

    def hydrate_properties(self, env: dict[str, Any]) -> None:

        # FIXME : recheck support for YNH_DEBIAN_VERSION, YNH_APP_UPSTREAM_VERSION etc

        def _recursive_apply(function: Callable, data: Any) -> Any:
            if isinstance(data, dict):
                return {
                    key: _recursive_apply(function, value) for key, value in data.items()
                }

            if isinstance(data, list):
                return [_recursive_apply(function, value) for value in data]

            return function(data)

        def _hydrate(value: str) -> str:
            from ..app import _hydrate_app_template
            if not isinstance(value, str):
                return value
            return _hydrate_app_template(
                value,
                env,
                raise_exception_if_missing_var=True,
            )

        for key, value in dict(self).items():
            if isinstance(value, (str, list, dict)):
                setattr(self, key, _recursive_apply(_hydrate, value))

    def get_setting(self, key: str) -> Any:
        from ..app import app_setting
        return app_setting(self.app, key)

    def set_setting(self, key: str, value: Any) -> None:
        from ..app import app_setting
        app_setting(self.app, key, value=value)

    def delete_setting(self, key: str) -> None:
        from ..app import app_setting
        app_setting(self.app, key, delete=True)

    def check_output_bash_snippet(self, snippet: str) -> tuple[str, str]:
        from ..app import _make_environment_for_app_script

        env = _make_environment_for_app_script(
            self.app,
            force_include_app_settings=True,
        )

        with tempfile.NamedTemporaryFile(prefix="ynh_") as fp:
            fp.write(snippet.encode())
            fp.seek(0)
            with tempfile.TemporaryFile() as stderr:
                out = check_output(f"bash {fp.name}", env=env, stderr=stderr)

                stderr.seek(0)
                err = stderr.read().decode()

        return out, err

    def _run_script(self, action: str, script: str, env: dict = {}) -> None:
        from ..app import _run_app_script_or_snippet
        _run_app_script_or_snippet(
            self.app,
            f"{action}_{self.type}",
            script,
            env={"YNH_HELPERS_VERSION": str(self.helpers_version).replace(".0", "")},
            workdir=self.workdir,
            raise_exception_if_failure=True
        )

    def provision_or_update(self) -> None:
        raise NotImplementedError

    def deprovision(self) -> None:
        raise NotImplementedError


class SourcesResource(AppResource):
    """
    Declare what are the sources / assets used by this app. Typically, this corresponds to some tarball published by the upstream project, that needs to be downloaded and extracted in the install dir using the ynh_setup_source helper.

    This resource is intended both to declare the assets, which will be parsed by ynh_setup_source during the app script runtime, AND to prefetch and validate the sha256sum of those asset before actually running the script, to be able to report an error early when the asset turns out to not be available for some reason.

    Various options are available to accomodate the behavior according to the asset structure

    ### Example

    ```toml
    [resources.sources]

        [resources.sources.main]
        url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.tar.gz"
        sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

        autoupdate.strategy = "latest_github_tag"
    ```

    Or more complex examples with several element, including one with asset that depends on the CPU architecture.
    With [packaging format v2.x](https://github.com/YunoHost/apps/blob/a5c97003e730dfd2303631a57ade2fc755f960ca/schemas/manifest.v2.schema.json#L169-L172), YunoHost currently supports `amd64`, `armhf`, `arm64` and `i386` architectures.

    ```toml
    [resources.sources]

        [resources.sources.main]
        in_subdir = false
        amd64.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.amd64.tar.gz"
        amd64.sha256 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
        i386.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.386.tar.gz"
        i386.sha256 = "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"
        armhf.url = "https://github.com/foo/bar/archive/refs/tags/v1.2.3.arm.tar.gz"
        armhf.sha256 = "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"

        autoupdate.strategy = "latest_github_release"
        autoupdate.asset.amd64 = ".*\\\\.amd64.tar.gz"
        autoupdate.asset.i386 = ".*\\\\.386.tar.gz"
        autoupdate.asset.armhf = ".*\\\\.arm.tar.gz"

        [resources.sources.zblerg]
        url = "https://zblerg.com/download/zblerg"
        sha256 = "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"
        format = "script"
        rename = "zblerg.sh"
    ```

    ### Properties (for each source)

    - `prefetch` : `true` (default) or `false`, wether or not to pre-fetch this asset during the provisioning phase of the resource. If several arch-dependent url are provided, YunoHost will only prefetch the one for the current system architecture.
    - `url` : the asset's URL
      - If the asset's URL depend on the architecture, you may instead provide `amd64.url`, `i386.url`, `armhf.url` and `arm64.url` (depending on what architectures are supported), using the same `dpkg --print-architecture` nomenclature as for the supported architecture key in the manifest
    - `sha256` : the asset's sha256sum. This is used both as an integrity check, and as a layer of security to protect against malicious actors which could have injected malicious code inside the asset...
      - Same as `url` : if the asset's URL depend on the architecture, you may instead provide `amd64.sha256`, `i386.sha256`, ...
    - `format` : The "format" of the asset. It is typically automatically guessed from the extension of the URL (or the mention of "tarball", "zipball" in the URL), but can be set explicitly:
      - `tar.gz`, `tar.xz`, `tar.bz2` : will use `tar` to extract the archive
      - `zip` : will use `unzip` to extract the archive
      - `docker` : useful to extract files from an already-built docker image (instead of rebuilding them locally). Will use `docker-image-extract`
      - `whatever`: whatever arbitrary value, not really meaningful except to imply that the file won't be extracted (eg because it's a .deb to be manually installed with dpkg/apt, or a script, or ...)
    - `in_subdir`: `true` (default) or `false`, depending on if there's an intermediate subdir in the archive before accessing the actual files. Can also be `N` (an integer) to handle special cases where there's `N` level of subdir to get rid of to actually access the files
    - `extract` : `true` or `false`. Defaults to `true` for archives such as `zip`, `tar.gz`, `tar.bz2`, ... Or defaults to `false` when `format` is not something that should be extracted. When `extract = false`, the file will only be `mv`ed to the location, possibly renamed using the `rename` value
    - `rename`: some string like `whatever_your_want`, to be used for convenience when `extract` is `false` and the default name of the file is not practical
    - `platform`: for example `linux/amd64` (defaults to `linux/$YNH_ARCH`) to be used in conjonction with `format = "docker"` to specify which architecture to extract for

    #### Regarding `autoupdate`

    Strictly speaking, this has nothing to do with the actual app install. `autoupdate` is expected to contain metadata for automatic maintenance / update of the app sources info in the manifest. It is meant to be a simpler replacement for "autoupdate" GitHub workflow mechanism.

    The infos are used by [this script](https://github.com/YunoHost/apps_tools/blob/main/autoupdate_app_sources/autoupdate_app_sources.py) which is ran by the YunoHost infrastructure periodically and will create the corresponding pull request automatically.

    The script will rely on the code repo specified in `code` in the upstream section of the manifest.

    The `autoupdate.strategy` is expected to be constructed like this: `latest_<gitforge>_<strategy>`

    You need to replace the `<gitforge>` in the strategy name by either `github`, `gitlab`, `gitea` or `forgejo`, as the autoupdater supports:

    - GitHub
    - GitLab (official and self-hosted instances)
    - Gitea & Forgejo instances

    And choose one strategy in the following ones:

    - `latest_<gitforge>_release` : similar to `latest_<gitforge>_tag`, but starting from the list of releases. Note that it's the only strategy that provides the changelog link in the PR message. Pre- or draft releases are ignored. Releases may have assets attached to them, in which case you can define:
      - `autoupdate.asset = "some regex"` (when there's only one asset to use). The regex is used to find the appropriate asset among the list of all assets
      - or several `autoupdate.asset.$arch = "some_regex"` (when the asset is arch-specific). The regex is used to find the appropriate asset for the specific arch among the list of assets
    - `latest_<gitforge>_tag` : look for the latest tag (by sorting tags and finding the "largest" version). Then using the corresponding tar.gz url. Tags containing `rc`, `beta`, `alpha`, `start` are ignored, and actually any tag which doesn't look like `x.y.z` or `vx.y.z`
    - `latest_<gitforge>_commit` : will use the latest commit on GitHub, and the corresponding tarball. If this is used for the 'main' source, it will also assume that the version is YYYY.MM.DD corresponding to the date of the commit.

    It is also possible to define `autoupdate.upstream` to use a different Git repository instead of the code repository from the upstream section of the manifest. This can be useful when, for example, the app uses other assets such as plugin from a different repository.

    If the upstream project provides non-standard tag or release names, you can fix this, with a regex with a matching group.

    For example, if tags look like `release-v4.1`, put:

    ```toml
    autoupdate.version_regex = "^release-v(.*)$"
    ```

    And the autoupdater will use the matched group (here: `4.1`) as the version.

    You can make sure that your autoupdate strategy is working well immediately (without waiting for the next check on the infra) by doing the following:

    1. Clone the apps_tools repository: `https://github.com/YunoHost/apps_tools`
    2. In `apps_tools` open a terminal to run the following commands:

        ```bash
        # Create test branch
        git checkout -b localtest

        # Create a Python virtual environment
        python -m venv venv
        source venv/bin/activate

        # Install dependencies (if you don't have pip already installed on your system, check https://pip.pypa.io/en/stable/installation)
        pip install -r requirements.txt

        # Run autoupdate script - replace '/path/to/myapp_ynh' with your actual local app path
        ./autoupdate_app_sources/autoupdate_app_sources.py '/path/to/myapp_ynh'
        ```

    3. If the return output includes:

        - `Apps udpated`, it ran successfully. Note that it will automatically make local changes in your app's `manifest.toml` (which can be discarded as they will be made automatically later online by the YNH infra);
        - `Apps failed`, the autoupdate stragegy is not working properly - check the debug info;
        - none of the above but `apps -> Autoupdater just ran, here are the results:`, it ran successfully but the app was already up to date.

    ### Provision/Update

    - For elements with `prefetch = true`, will download the asset (for the appropriate architecture) and store them in `/var/cache/yunohost/download/$app/$source_id`, to be later picked up by `ynh_setup_source`. (NB: this only happens during install and upgrade, not restore)

    ### Deprovision

    - Nothing (just cleanup the cache)
    """

    type = "sources"
    multi = True

    url: str | dict[Literal["amd64", "i386", "armhf", "arm64"], str]
    sha256: str | dict[Literal["amd64", "i386", "armhf", "arm64"], str]
    prefetch: bool = True
    format: str | None = None
    in_subdir: bool | None = None
    extract: bool | None = None
    rename: str | None = None
    platform: str | None = None
    autoupdate: dict | None = None

    exposed_properties = ["prefetch", "url", "sha256", "prefetch", "format", "in_subdir", "extract", "rename", "platform", "autoupdate"]

    action_is_restore: str | None

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        # Writing 'amd64.url = ...' in the manifest is practical and neat,
        # but not easy to handle in term of datastructure and typing
        # hence we invert it to have url (str) = "..."" (arch-agnostic) or url (dict[Literal, str]) = {'amd64': "...", ...} (arch-specific)
        url_per_arch = {}
        sha256_per_arch = {}
        for arch in ["amd64", "i386", "armhf", "arm64"]:
            if arch in kwargs:
                if not isinstance(kwargs[arch], dict) or "url" not in kwargs[arch] or "sha256" not in kwargs[arch]:
                    raise YunohostPackagingError(f"Uhoh, it sounds like there's an issue when parsing arch-specific info for source '{kwargs['id']}', expected to find a dict with an 'url' and 'sha256' key")
                arch_infos = kwargs.pop(arch)
                url_per_arch[arch] = arch_infos["url"]
                sha256_per_arch[arch] = arch_infos["sha256"]

        if url_per_arch:
            if "url" in kwargs or "sha256" in kwargs:
                raise YunohostPackagingError(f"Packager, you can't mix arch-specific and arch-agnostic url/sha256 (when initializing source '{kwargs['id']}')")
            kwargs["url"] = url_per_arch
            kwargs["sha256"] = sha256_per_arch

        super().__init__(**kwargs)

        self.action_is_restore = kwargs["env"].get("YNH_APP_ACTION") == "restore"

    def deprovision(self) -> None:
        cache_dir = Path(SOURCES_CACHE_DIR) / self.app
        cache_file = cache_dir / self.id
        if cache_file.exists():
            cache_file.unlink()
        if not list(cache_dir.iterdir()):
            cache_dir.rmdir()

    def provision_or_update(self) -> None:
        # Don't prefetch stuff during restore
        if self.action_is_restore == "restore":
            return

        cache_dir = Path(SOURCES_CACHE_DIR) / self.app
        cache_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        # We later give ownership to $app in the system_user
        chown(str(cache_dir), "root", recursive=True)

        if not self.prefetch:
            return

        if isinstance(self.url, dict):
            assert isinstance(self.sha256, dict)
            arch = system_arch()
            if arch not in self.url:
                raise YunohostPackagingError(
                    f"In resources.sources: it looks like you forgot to define url/sha256 or {arch}.url/{arch}.sha256"
                )
            url = self.url[arch]
            sha256 = self.sha256[arch]
        else:
            url = self.url
            assert isinstance(self.sha256, str)
            sha256 = self.sha256
        self.prefetch_asset(url, sha256)

    def prefetch_asset(self, url: str, expected_sha256: str) -> None:
        logger.debug(f"Prefetching asset {self.id}: {url} ...")

        cache_file = Path(SOURCES_CACHE_DIR) / self.app / self.id

        # NB: we use wget and not requests.get() because we want to output to a file (ie avoid ending up with the full archive in RAM)
        # AND the nice --tries, --no-dns-cache, --timeout options ...
        p = subprocess.Popen(
            [
                "/usr/bin/wget",
                "--tries=3",
                "--no-dns-cache",
                "--timeout=900",
                "--no-verbose",
                "--output-document=" + str(cache_file),
                url,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, _ = p.communicate()
        returncode = p.returncode
        if returncode != 0:
            if cache_file.exists():
                cache_file.unlink()
            raise YunohostError(
                "app_failed_to_download_asset",
                source_id=self.id,
                url=url,
                app=self.app,
                out=out.decode(),
            )

        assert cache_file.exists(), (
            f"For some reason, wget worked but {cache_file} doesnt exists?"
        )

        computed_sha256 = check_output(f"sha256sum {cache_file}").split()[0]
        if computed_sha256 != expected_sha256:
            size = check_output(f"du -hs {cache_file}").split()[0]
            cache_file.unlink()
            raise YunohostError(
                "app_corrupt_source",
                source_id=self.id,
                url=url,
                app=self.app,
                expected_sha256=expected_sha256,
                computed_sha256=computed_sha256,
                size=size,
            )


class PermissionsResource(AppResource):
    """
    Configure the SSO permissions/tiles. Typically, webapps are expected to have a 'main' permission mapped to '/', meaning that a tile pointing to the `$domain/$path` will be available in the SSO for users allowed to access that app.

    Additional permissions can be created, typically to have a specific tile and/or access rules for the admin part of a webapp.

    The list of allowed user/groups may be initialized using the content of the `init_{perm}_permission` question from the manifest, hence `init_main_permission` replaces the `is_public` question and shall contain a group name (typically, `all_users` or `visitors`).

    ### Example

    ```toml
    [resources.permissions]
    main.url = "/"
    # (these two previous lines should be enough in the majority of cases)

    admin.url = "/admin"
    admin.show_tile = false
    admin.allowed = "admins"   # Assuming the "admins" group exists (cf future developments ;))
    ```

    ### Properties (for each perm name)

    - `url`: The relative URI corresponding to this permission. Typically `/` or `/something`. This property may be omitted for non-web permissions. Can also be a regex, prefixed by `re:` like `re:/api/[A-Z]*$`.
    - `show_tile`: (default: `true` if `url` is defined) Wether or not a tile should be displayed for that permission in the user portal
    - `allowed`: (default: nobody) The group initially allowed to access this perm, if `init_{perm}_permission` is not defined in the manifest questions. Note that the admin may tweak who is allowed/unallowed on that permission later on, this is only meant to **initialize** the permission.
    - `auth_header`: (default: `true`) Define for the URL of this permission, if SSOwat pass the authentication header to the application. Default is true
    - `protected`: (default: `false`) Define if this permission is protected. If it is protected the administrator won't be able to add or remove the visitors group of this permission. Defaults to 'false'.
    - `additional_urls`: (default: none) List of additional URL for which access will be allowed/forbidden

    ### Provision/Update

    - Delete any permissions that may exist and be related to this app yet is not declared anymore
    - Loop over the declared permissions and create them if needed or update them with the new values

    ### Deprovision

    - Delete all permission related to this app

    ### Legacy management

    - Legacy `is_public` setting will be deleted if it exists
    """

    # Notes for future ?
    # deep_clean  -> delete permissions for any __APP__.foobar where app not in app list...
    # backup -> handled elsewhere by the core, should be integrated in there (dump .ldif/yml?)
    # restore -> handled by the core, should be integrated in there (restore .ldif/yml?)

    type = "permissions"
    priority = 80

    default_properties: Dict[str, Any] = {}

    default_perm_properties: Dict[str, Any] = {
        "url": None,
        "additional_urls": [],
        "auth_header": True,
        "allowed": None,
        "show_tile": None,  # To be automagically set to True by default if an url is defined and show_tile not provided
        "protected": False,
    }

    permissions: Dict[str, Dict[str, Any]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        # FIXME : if url != None, we should check that there's indeed a domain/path defined ? ie that app is a webapp

        # Validate packager-provided infos
        for perm, infos in properties.items():
            if "auth_header" in infos and not isinstance(
                infos.get("auth_header"), bool
            ):
                raise YunohostPackagingError(
                    f"In manifest, for permission '{perm}', 'auth_header' should be a boolean"
                )
            if "show_tile" in infos and not isinstance(infos.get("show_tile"), bool):
                raise YunohostPackagingError(
                    f"In manifest, for permission '{perm}', 'show_tile' should be a boolean"
                )
            if "protected" in infos and not isinstance(infos.get("protected"), bool):
                raise YunohostPackagingError(
                    f"In manifest, for permission '{perm}', 'protected' should be a boolean"
                )
            if "additional_urls" in infos and not isinstance(
                infos.get("additional_urls"), list
            ):
                raise YunohostPackagingError(
                    f"In manifest, for permission '{perm}', 'additional_urls' should be a list",
                )

        if "main" not in properties:
            properties["main"] = copy.copy(self.default_perm_properties)

        for perm, infos in properties.items():
            properties[perm] = copy.copy(self.default_perm_properties)
            properties[perm].update(infos)
            if properties[perm]["show_tile"] is None:
                properties[perm]["show_tile"] = bool(properties[perm]["url"])

        if properties["main"]["url"] is not None and (
            not isinstance(properties["main"].get("url"), str)
            or properties["main"]["url"] != "/"
        ):
            raise YunohostPackagingError(
                "URL for the 'main' permission should be '/' for webapps (or left undefined for non-webapps). Note that / refers to the install url of the app, i.e $domain.tld/$path/"
            )

        super().__init__({"permissions": properties}, *args, **kwargs)

        from ..app import _get_app_settings, _hydrate_app_template

        settings = _get_app_settings(self.app)
        for perm, infos in self.permissions.items():
            if infos.get("url") and "__" in infos.get("url"):  # type: ignore
                infos["url"] = _hydrate_app_template(infos["url"], settings)

            if infos.get("additional_urls"):
                infos["additional_urls"] = [
                    _hydrate_app_template(url, settings)
                    for url in infos["additional_urls"]
                ]

    def provision_or_update(self, context: Dict = {}):
        from ..app import app_ssowatconf
        from ..permission import (
            _sync_permissions_with_ldap,
            permission_create,
            permission_delete,
            permission_url,
            user_permission_update,
        )

        # Delete legacy is_public setting if not already done
        self.delete_setting("is_public")

        # Detect that we're using a full-domain app,
        # in which case we probably need to automagically
        # define the "path" setting with "/"
        if (
            isinstance(self.permissions["main"]["url"], str)
            and self.get_setting("domain")
            and not self.get_setting("path")
        ):
            self.set_setting("path", "/")

        existing_perms = list((self.get_setting("_permissions") or {}).keys())
        for perm in existing_perms:
            if perm not in self.permissions.keys():
                permission_delete(f"{self.app}.{perm}", force=True, sync_perm=False)

        for perm, infos in self.permissions.items():
            perm_id = f"{self.app}.{perm}"
            if perm not in existing_perms:
                # Use the 'allowed' key from the manifest,
                # or use the 'init_{perm}_permission' from the install questions
                # which is temporarily saved as a setting as an ugly hack to pass the info to this piece of code...
                init_allowed = (
                    infos["allowed"]
                    or self.get_setting(f"init_{perm}_permission")
                    or []
                )

                # If we're choosing 'visitors' from the init_{perm}_permission question, add all_users too
                if not infos["allowed"] and init_allowed == "visitors":
                    init_allowed = ["visitors", "all_users"]

                permission_create(
                    perm_id,
                    allowed=init_allowed,
                    url=infos["url"],
                    additional_urls=infos["additional_urls"],
                    auth_header=infos["auth_header"],
                    sync_perm=False,
                )
                self.delete_setting(f"init_{perm}_permission")

            user_permission_update(
                perm_id,
                show_tile=infos["show_tile"],
                protected=infos["protected"],
                sync_perm=False,
                log_success_as_debug=True,
            )
            permission_url(
                perm_id,
                url=infos["url"],
                set_url=infos["additional_urls"],
                auth_header=infos["auth_header"],
                sync_perm=False,
            )

        _sync_permissions_with_ldap()
        app_ssowatconf()

    def deprovision(self, context: Dict = {}):
        from ..app import app_ssowatconf
        from ..permission import (
            _sync_permissions_with_ldap,
            permission_delete,
        )

        existing_perms = list((self.get_setting("_permissions") or {}).keys())
        for perm in existing_perms:
            permission_delete(f"{self.app}.{perm}", force=True, sync_perm=False)

        _sync_permissions_with_ldap()
        app_ssowatconf()


class SystemuserAppResource(AppResource):
    """
    Provision a system user to be used by the app. The username is exactly equal to the app id

    ### Example

    ```toml
    [resources.system_user]
    # (empty - defaults are usually okay)
    ```

    ### Properties

    - `allow_ssh`: (default: False) Adds the user to the ssh.app group, allowing SSH connection via this user
    - `allow_sftp`: (default: False) Adds the user to the sftp.app group, allowing SFTP connection via this user
    - `allow_email`: (default: False) Enable authentication on the mail stack for the system user and send mail using `__APP__@__DOMAIN__`. A `mail_pwd` setting is automatically defined (similar to `db_pwd` for databases). You can then configure the app to use `__APP__` and `__MAIL_PWD__` as SMTP credentials (with host 127.0.0.1). You can also tweak the user-part of the domain-part of the email used by manually defining a custom setting `mail_user` or `mail_domain`
    - `home`: (default: `/var/www/__APP__`) Defines the home property for this user. NB: unfortunately you can't simply use `__INSTALL_DIR__` or `__DATA_DIR__` for now

    ### Provision/Update

    - will create the system user if it doesn't exists yet
    - will add/remove the ssh/sftp.app groups

    ### Deprovision

    - deletes the user and group
    """

    # Notes for future?
    #
    # deep_clean  -> uuuuh ? delete any user that could correspond to an app x_x ?
    #
    # backup -> nothing
    # restore -> provision

    type = "system_user"
    priority = 20

    default_properties: Dict[str, Any] = {
        "allow_ssh": False,
        "allow_sftp": False,
        "allow_email": False,
        "home": "/var/www/__APP__",
    }

    # FIXME : wat do regarding ssl-cert, multimedia, and other groups

    allow_ssh: bool = False
    allow_sftp: bool = False
    allow_email: bool = False
    home: str = ""

    def provision_or_update(self, context: Dict = {}):
        from ..app import regen_mail_app_user_config_for_dovecot_and_postfix

        # FIXME : validate that no yunohost user exists with that name?
        # and/or that no system user exists during install ?

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") != 0:
            # FIXME: improve logging ? os.system wont log stdout / stderr
            cmd = f"useradd --system --user-group {self.app} --home-dir {self.home} --no-create-home"
            ret = os.system(cmd)
            assert ret == 0, f"useradd command failed with exit code {ret}"

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") != 0:
            raise YunohostError(
                f"Failed to create system user for {self.app}", raw_msg=True
            )

        # Update groups
        groups = set(check_output(f"groups {self.app}").strip().split()[2:])

        if self.allow_ssh:
            groups.add("ssh.app")
        elif "ssh.app" in groups:
            groups.remove("ssh.app")

        if self.allow_sftp:
            groups.add("sftp.app")
        elif "sftp.app" in groups:
            groups.remove("sftp.app")

        os.system(f"usermod -G {','.join(groups)} {self.app}")

        # Update home dir
        raw_user_line_in_etc_passwd = check_output(f"getent passwd {self.app}").strip()
        user_infos = raw_user_line_in_etc_passwd.split(":")
        current_home = user_infos[5]
        if current_home != self.home:
            ret = os.system(f"usermod --home {self.home} {self.app} 2>/dev/null")
            # Most of the time this won't work because apparently we can't change the home dir while being logged-in -_-
            # So we gotta brute force by replacing the line in /etc/passwd T_T
            if ret != 0:
                user_infos[5] = self.home
                new_raw_user_line_in_etc_passwd = ":".join(user_infos)
                os.system(
                    f"sed -i 's@{raw_user_line_in_etc_passwd}@{new_raw_user_line_in_etc_passwd}@g' /etc/passwd"
                )

        # Update mail-related stuff
        if self.allow_email:
            mail_pwd = self.get_setting("mail_pwd")
            if not mail_pwd:
                mail_pwd = random_ascii(24)
                self.set_setting("mail_pwd", mail_pwd)

            regen_mail_app_user_config_for_dovecot_and_postfix()
        else:
            self.delete_setting("mail_pwd")
            if (
                os.system(
                    f"grep --quiet ' {self.app}$' /etc/postfix/app_senders_login_maps"
                )
                == 0
                or os.system(
                    f"grep --quiet '^{self.app}:' /etc/dovecot/app-senders-passwd"
                )
                == 0
            ):
                regen_mail_app_user_config_for_dovecot_and_postfix()

        # Allow user to access pre-fetch source (or create files in there during scripts)
        if os.path.isdir(f"{SOURCES_CACHE_DIR}/{self.app}"):
            chown(f"{SOURCES_CACHE_DIR}/{self.app}", self.app, recursive=True)

    def deprovision(self, context: Dict = {}):
        from ..app import regen_mail_app_user_config_for_dovecot_and_postfix

        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") == 0:
            os.system(f"deluser {self.app} >/dev/null")
        if os.system(f"getent passwd {self.app} >/dev/null 2>/dev/null") == 0:
            raise YunohostError(
                f"Failed to delete system user for {self.app}", raw_msg=True
            )

        if os.system(f"getent group {self.app} >/dev/null 2>/dev/null") == 0:
            os.system(f"delgroup {self.app} >/dev/null")
        if os.system(f"getent group {self.app} >/dev/null 2>/dev/null") == 0:
            raise YunohostError(
                f"Failed to delete system user for {self.app}", raw_msg=True
            )

        self.delete_setting("mail_pwd")
        if (
            os.system(
                f"grep --quiet ' {self.app}$' /etc/postfix/app_senders_login_maps"
            )
            == 0
            or os.system(f"grep --quiet '^{self.app}:' /etc/dovecot/app-senders-passwd")
            == 0
        ):
            regen_mail_app_user_config_for_dovecot_and_postfix()

        # FIXME : better logging and error handling, add stdout/stderr from the deluser/delgroup commands...


class InstalldirAppResource(AppResource):
    """
    Creates a directory to be used by the app as the installation directory, typically where the app sources and assets are located. The corresponding path is stored in the settings as `install_dir`

    ### Example

    ```toml
    [resources.install_dir]
    # (empty - defaults are usually okay)
    ```

    ### Properties

    - `dir`: (default: `/var/www/__APP__`) The full path of the install dir
    - `owner`: (default: `__APP__:rwx`) The owner (and owner permissions) for the install dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the install dir

    ### Provision/Update

    - during install, the folder will be deleted if it already exists (FIXME: is this what we want?)
    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - (re-)apply permissions (only on the folder itself, not recursively)
    - save the value of `dir` as `install_dir` in the app's settings, which can be then used by the app scripts (`$install_dir`) and conf templates (`__INSTALL_DIR__`)

    ### Deprovision

    - recursively deletes the directory if it exists

    ### Legacy management

    - In the past, the setting was called `final_path`. The code will automatically rename it as `install_dir`.
    - As explained in the 'Provision/Update' section, the folder will also be moved if the location changed

    """

    # Notes for future?
    # deep_clean  -> uuuuh ? delete any dir in /var/www/ that would not correspond to an app x_x ?
    # backup -> cp install dir
    # restore -> cp install dir

    type = "install_dir"
    priority = 30

    default_properties: Dict[str, Any] = {
        "dir": "/var/www/__APP__",
        "owner": "__APP__:rwx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    owner: str = ""
    group: str = ""

    # FIXME: change default dir to /opt/stuff if app ain't a webapp...

    def provision_or_update(self, context: Dict = {}):
        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        current_install_dir = self.get_setting("install_dir") or self.get_setting(
            "final_path"
        )

        # If during install, /var/www/$app already exists, assume that it's okay to remove and recreate it
        # FIXME : is this the right thing to do ?
        if not current_install_dir and os.path.isdir(self.dir):
            rm(self.dir, recursive=True)

        # isdir will be True if the path is a symlink pointing to a dir
        # This should cover cases where people moved the data dir to another place via a symlink (ie we dont enter the if)
        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            # FIXME: confirm that's what we wanna do
            # Maybe a middle ground could be to compute the size, check that it's not too crazy (eg > 1G idk),
            # and check for available space on the destination
            if current_install_dir and os.path.isdir(current_install_dir):
                logger.warning(
                    f"Moving {current_install_dir} to {self.dir}... (this may take a while)"
                )
                shutil.move(current_install_dir, self.dir)
            else:
                mkdir(self.dir, parents=True)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (
            (4 if "r" in owner_perm else 0)
            + (2 if "w" in owner_perm else 0)
            + (1 if "x" in owner_perm else 0)
        )
        group_perm_octal = (
            (4 if "r" in group_perm else 0)
            + (2 if "w" in group_perm else 0)
            + (1 if "x" in group_perm else 0)
        )

        perm_octal = 0o100 * owner_perm_octal + 0o010 * group_perm_octal

        # NB: we use realpath here to cover cases where self.dir could actually be a symlink
        # in which case we want to apply the perm to the pointed dir, not to the symlink
        chmod(os.path.realpath(self.dir), perm_octal)
        chown(os.path.realpath(self.dir), owner, group)
        # FIXME: shall we apply permissions recursively ?

        self.set_setting("install_dir", self.dir)
        self.delete_setting("final_path")  # Legacy

    def deprovision(self, context: Dict = {}):
        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        # FIXME : check that self.dir has a sensible value to prevent catastrophes
        if os.path.isdir(self.dir):
            rm(self.dir, recursive=True)
        # FIXME : in fact we should delete settings to be consistent


class DatadirAppResource(AppResource):
    """
    Creates a directory to be used by the app as the data store directory, typically where the app multimedia or large assets added by users are located. The corresponding path is stored in the settings as `data_dir`. This resource behaves very similarly to install_dir.

    ### Example

    ```toml
    [resources.data_dir]
    # (empty - defaults are usually okay)
    ```

    ### Properties

    - `dir`: (default: `/home/yunohost.app/__APP__`) The full path of the data dir
    - `subdirs`: (default: empty list) A list of subdirs to initialize inside the data dir. For example, `['foo', 'bar']`
    - `owner`: (default: `__APP__:rwx`) The owner (and owner permissions) for the data dir
    - `group`: (default: `__APP__:rx`) The group (and group permissions) for the data dir

    ### Provision/Update

    - if the dir path changed and a folder exists at the old location, the folder will be `mv`'ed to the new location
    - otherwise, creates the directory if it doesn't exists yet
    - create each subdir declared and which do not exist already
    - (re-)apply permissions (only on the folder itself and declared subdirs, not recursively)
    - save the value of `dir` as `data_dir` in the app's settings, which can be then used by the app scripts (`$data_dir`) and conf templates (`__DATA_DIR__`)

    ### Deprovision

    - (only if the purge option is chosen by the user) recursively deletes the directory if it exists
    - also delete the corresponding setting

    ### Legacy management

    - In the past, the setting may have been called `datadir`. The code will automatically rename it as `data_dir`.
    - As explained in the 'Provision/Update' section, the folder will also be moved if the location changed

    """

    # notes for future ?
    # deep_clean  -> zblerg idk nothing
    # backup -> cp data dir ? (if not backup_core_only)
    # restore -> cp data dir ? (if in backup)

    type = "data_dir"
    priority = 40

    default_properties: Dict[str, Any] = {
        "dir": "/home/yunohost.app/__APP__",
        "subdirs": [],
        "owner": "__APP__:rwx",
        "group": "__APP__:rx",
    }

    dir: str = ""
    subdirs: list = []
    owner: str = ""
    group: str = ""

    def provision_or_update(self, context: Dict = {}):
        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        current_data_dir = self.get_setting("data_dir") or self.get_setting("datadir")

        # isdir will be True if the path is a symlink pointing to a dir
        # This should cover cases where people moved the data dir to another place via a symlink (ie we dont enter the if)
        if not os.path.isdir(self.dir):
            # Handle case where install location changed, in which case we shall move the existing install dir
            # FIXME: same as install_dir, is this what we want ?
            if current_data_dir and os.path.isdir(current_data_dir):
                logger.warning(
                    f"Moving {current_data_dir} to {self.dir}... (this may take a while)"
                )
                shutil.move(current_data_dir, self.dir)
            else:
                mkdir(self.dir, parents=True)

        for subdir in self.subdirs:
            full_path = os.path.join(self.dir, subdir)
            if not os.path.isdir(full_path):
                mkdir(full_path, parents=True)

        owner, owner_perm = self.owner.split(":")
        group, group_perm = self.group.split(":")
        owner_perm_octal = (
            (4 if "r" in owner_perm else 0)
            + (2 if "w" in owner_perm else 0)
            + (1 if "x" in owner_perm else 0)
        )
        group_perm_octal = (
            (4 if "r" in group_perm else 0)
            + (2 if "w" in group_perm else 0)
            + (1 if "x" in group_perm else 0)
        )
        perm_octal = 0o100 * owner_perm_octal + 0o010 * group_perm_octal

        # NB: we use realpath here to cover cases where self.dir could actually be a symlink
        # in which case we want to apply the perm to the pointed dir, not to the symlink
        chmod(os.path.realpath(self.dir), perm_octal)
        chown(os.path.realpath(self.dir), owner, group)
        for subdir in self.subdirs:
            full_path = os.path.join(self.dir, subdir)
            chmod(os.path.realpath(full_path), perm_octal)
            chown(os.path.realpath(full_path), owner, group)

        self.set_setting("data_dir", self.dir)
        self.delete_setting("datadir")  # Legacy

    def deprovision(self, context: Dict = {}):
        assert self.dir.strip()  # Be paranoid about self.dir being empty...
        assert self.owner.strip()
        assert self.group.strip()

        if context.get("purge_data_dir", False) and os.path.isdir(self.dir):
            rm(self.dir, recursive=True)

        self.delete_setting("data_dir")


class AptDependenciesAppResource(AppResource):
    """
    Create a virtual package in apt, depending on the list of specified packages that the app needs. The virtual packages is called `$app-ynh-deps` (with `_` being replaced by `-` in the app name, see `ynh_install_app_dependencies`)

    ### Example

    ```toml
    [resources.apt]
    packages = ["nyancat", "lolcat", "sl"]

    # (this part is optional and corresponds to the legacy ynh_install_extra_app_dependencies helper)
    extras.yarn.repo = "deb https://dl.yarnpkg.com/debian/ stable main"
    extras.yarn.key = "https://dl.yarnpkg.com/debian/pubkey.gpg"
    extras.yarn.packages = ["yarn"]
    ```

    ### Properties

    - `packages`: List of packages to be installed via `apt`
    - `packages_from_raw_bash`: A multi-line bash snippet (using triple quotes as open/close) which should echo additional packages to be installed. Meant to be used for packages to be conditionally installed depending on architecture, debian version, install questions, or other logic.
    - `extras`: A dict of (repo, key, packages) corresponding to "extra" repositories to fetch dependencies from

    ### Provision/Update

    - The code literally calls the bash helpers `ynh_install_app_dependencies` and `ynh_install_extra_app_dependencies`, similar to what happens in v1.
    - Note that when `packages` contains some phpX.Y-foobar dependencies, this will automagically define a `phpversion` setting equal to `X.Y` which can therefore be used in app scripts ($phpversion) or templates (`__PHPVERSION__`)

    ### Deprovision

    - The code literally calls the bash helper `ynh_remove_app_dependencies`
    """

    # Notes for future?
    # deep_clean  -> remove any __APP__-ynh-deps for app not in app list
    # backup -> nothing
    # restore = provision

    type = "apt"
    priority = 50

    default_properties: Dict[str, Any] = {"packages": [], "extras": {}}

    packages: List = []
    packages_from_raw_bash: str = ""
    extras: Dict[str, Dict[str, Union[str, List]]] = {}

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        super().__init__(properties, *args, **kwargs)

        if isinstance(self.packages, str):
            if self.packages.strip() == "":
                self.packages = []
            else:
                self.packages = [value.strip() for value in self.packages.split(",")]

        if self.packages_from_raw_bash:
            out, err = self.check_output_bash_snippet(self.packages_from_raw_bash)
            if err:
                logger.error(
                    "Error while running apt resource packages_from_raw_bash snippet:"
                )
                logger.error(err)
            self.packages += out.split("\n")

        for key, values in self.extras.items():
            if isinstance(values.get("packages"), str):
                values["packages"] = [
                    value.strip()
                    for value in values["packages"].split(",")  # type: ignore
                ]

            if isinstance(values.get("packages_from_raw_bash"), str):
                out, err = self.check_output_bash_snippet(
                    values.get("packages_from_raw_bash")
                )
                if err:
                    logger.error(
                        f"Error while running apt resource packages_from_raw_bash snippet for '{key}' extras:"
                    )
                    logger.error(err)
                values["packages"] = values.get("packages", []) + [  # type: ignore
                    value.strip() for value in out.split("\n") if value.strip()
                ]

            if (
                not isinstance(values.get("repo"), str)
                or not isinstance(values.get("key"), str)
                or not isinstance(values.get("packages"), list)
            ):
                raise YunohostPackagingError(
                    "In apt resource in the manifest: 'extras' repo should have the keys 'repo', 'key' defined as strings, 'packages' defined as list or 'packages_from_raw_bash' defined as string",
                )

        # Drop 'extras' entries associated to no packages
        self.extras = {
            key: values for key, values in self.extras.items() if values["packages"]
        }

        # Yarn repository is now provided by the core.
        # Let's "move" any extra apt resources depending on yarn to the standard packages list.
        for key in list(self.extras.keys()):
            if self.extras[key][
                "repo"
            ] == "deb https://dl.yarnpkg.com/debian/ stable main" and self.extras[key][
                "packages"
            ] == ["yarn"]:
                self.packages.append("yarn")
                del self.extras[key]

    def provision_or_update(self, context: Dict = {}):
        if self.helpers_version >= 2.1:
            ynh_apt_install_dependencies = "ynh_apt_install_dependencies"
            ynh_apt_install_dependencies_from_extra_repository = (
                "ynh_apt_install_dependencies_from_extra_repository"
            )
        else:
            ynh_apt_install_dependencies = "ynh_install_app_dependencies"
            ynh_apt_install_dependencies_from_extra_repository = (
                "ynh_install_extra_app_dependencies"
            )

        script = ""
        if self.packages:
            script += " ".join([ynh_apt_install_dependencies, *self.packages])
        for repo, values in self.extras.items():
            script += "\n" + " ".join(
                [
                    ynh_apt_install_dependencies_from_extra_repository,
                    f"--repo='{values['repo']}'",
                    f"--key='{values['key']}'",
                    f"--package='{' '.join(values['packages'])}'",
                ]
            )
            # FIXME : we're feeding the raw value of values['packages'] to the helper .. if we want to be consistent, may they should be comma-separated, though in the majority of cases, only a single package is installed from an extra repo..

        self._run_script("provision_or_update", script)

    def deprovision(self, context: Dict = {}):
        if self.helpers_version >= 2.1:
            ynh_apt_remove_dependencies = "ynh_apt_remove_dependencies"
        else:
            ynh_apt_remove_dependencies = "ynh_remove_app_dependencies"

        self._run_script("deprovision", ynh_apt_remove_dependencies)


class PortsResource(AppResource):
    """
    Book port(s) to be used by the app, typically to be used to the internal reverse-proxy between nginx and the app process.

    Note that because multiple ports can be booked, each properties is prefixed by the name of the port. `main` is a special name and will correspond to the setting `$port`, whereas for example `xmpp_client` will correspond to the setting `$port_xmpp_client`.

    ### Example

    ```toml
    [resources.ports]
    # (empty should be fine for most apps... though you can customize stuff if absolutely needed)


    main.default = 12345    # if you really want to specify a prefered value .. but shouldnt matter in the majority of cases

    xmpp_client.default = 5222  # if you need another port, pick a name for it (here, "xmpp_client")
    xmpp_client.exposed = "TCP" # here, we're telling that the port needs to be publicly exposed on TCP on the firewall
    ```

    ### Properties (for every port name)

    - `default`: The prefered value for the port. If this port is already being used by another process right now, or is booked in another app's setting, the code will increment the value until it finds a free port and store that value as the setting. If no value is specified, a random value between 10000 and 60000 is used.
    - `exposed`: (default: `false`) Wether this port should be opened on the firewall and be publicly reachable. This should be kept to `false` for the majority of apps than only need a port for internal reverse-proxying! Possible values: `false`, `true`(=`Both`), `Both`, `TCP`, `UDP`. This will result in the port being opened on the firewall, and the diagnosis checking that a program answers on that port.
    - `fixed`: (default: `false`) Tells that the app absolutely needs the specific value provided in `default`, typically because it's needed for a specific protocol

    ### Provision/Update (for every port name)

    - If not already booked, look for a free port, starting with the `default` value (or a random value between 10000 and 60000 if no `default` set)
    - If `exposed` is not `false`, open the port in the firewall accordingly - otherwise make sure it's closed.
    - The value of the port is stored in the `$port` setting for the `main` port, or `$port_NAME` for other `NAME`s

    ### Deprovision

    - Close the ports on the firewall if relevant
    - Deletes all the port settings

    ### Legacy management

    - In the past, some settings may have been named `NAME_port` instead of `port_NAME`, in which case the code will automatically rename the old setting.
    """

    # Notes for future?
    # deep_clean  -> ?
    # backup -> nothing (backup port setting)
    # restore -> nothing (restore port setting)

    type = "ports"
    priority = 70

    default_properties: Dict[str, Any] = {}

    default_port_properties = {
        "default": None,
        "exposed": False,  # or True(="Both"), "TCP", "UDP"
        "fixed": False,
        "upnp": False,
    }

    ports: Dict[str, Dict[str, Any]]

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        if "main" not in properties:
            properties["main"] = {}

        for port, infos in properties.items():
            properties[port] = copy.copy(self.default_port_properties)
            properties[port].update(infos)

            if properties[port]["default"] is None:
                properties[port]["default"] = random.randint(10000, 60000)

        # This is to prevent using twice the same port during provisionning.
        self.ports_used_by_self: list[int] = []

        super().__init__({"ports": properties}, *args, **kwargs)

    def _port_is_used(self, port):
        # FIXME : this could be less brutal than two os.system...
        used_by_process = (
            os.system(
                "ss --numeric --listening --tcp --udp | awk '{print$5}' | grep --quiet --extended-regexp ':%s$'"
                % port
            )
            == 0
        )
        # This second command is mean to cover (most) case where an app is using a port yet ain't currently using it for some reason (typically service ain't up)
        used_by_app = (
            os.system(
                f"grep --quiet --extended-regexp \"port: '?{port}'?\" /etc/yunohost/apps/*/settings.yml"
            )
            == 0
        )
        used_by_self_provisioning = port in self.ports_used_by_self

        return used_by_process or used_by_app or used_by_self_provisioning

    def _exposed_to_protos(self, exposed: str | bool) -> list[str]:
        if isinstance(exposed, bool):
            return ["tcp"] if exposed else []
        if exposed.lower() == "both":
            return ["tcp", "udp"]
        return [exposed.lower()]

    def provision_or_update(self, context: Dict = {}):
        from ..firewall import YunoFirewall

        firewall = YunoFirewall()

        for name, infos in self.ports.items():
            setting_name = f"port_{name}" if name != "main" else "port"
            port_value = self.get_setting(setting_name)
            if not port_value and name != "main":
                # Automigrate from legacy setting foobar_port (instead of port_foobar)
                legacy_setting_name = f"{name}_port"
                port_value = self.get_setting(legacy_setting_name)
                if port_value:
                    self.set_setting(setting_name, port_value)
                    self.delete_setting(legacy_setting_name)
                    continue

            if not port_value:
                port_value = infos["default"]

                if infos["fixed"]:
                    if self._port_is_used(port_value):
                        raise YunohostValidationError(
                            f"Port {port_value} is already used by another process or app.",
                            raw_msg=True,
                        )
                else:
                    while self._port_is_used(port_value):
                        port_value += 1

            self.ports_used_by_self.append(port_value)
            self.set_setting(setting_name, port_value)

            comment = f"{self.app} {name}"
            if infos["exposed"]:
                for proto in self._exposed_to_protos(infos["exposed"]):
                    firewall.open_port(proto, port_value, comment, infos["upnp"])
            else:
                for proto in ["tcp", "udp"]:
                    firewall.close_port(proto, port_value)

        if firewall.need_reload:
            firewall.apply()

    def deprovision(self, context: Dict = {}):
        from ..firewall import YunoFirewall

        firewall = YunoFirewall()

        for name, infos in self.ports.items():
            setting_name = f"port_{name}" if name != "main" else "port"
            value = self.get_setting(setting_name)
            self.delete_setting(setting_name)
            if value and str(value).strip():
                for proto in self._exposed_to_protos(infos["exposed"]):
                    firewall.delete_port(proto, value)

        if firewall.need_reload:
            firewall.apply()


class DatabaseAppResource(AppResource):
    """
    Initialize a database, either using MySQL or Postgresql. Relevant DB infos are stored in settings `$db_name`, `$db_user` and `$db_pwd`.

    NB: only one DB can be handled in such a way (is there really an app that would need two completely different DB ?...)

    NB2: no automagic migration will happen in an suddenly change `type` from `mysql` to `postgresql` or viceversa in its life

    ### Example

    ```toml
    [resources.database]
    type = "mysql"   # or : "postgresql". Only these two values are supported
    ```

    ### Properties

    - `type`: The database type, either `mysql` or `postgresql`

    ### Provision/Update

    - (Re)set the `$db_name` and `$db_user` settings with the sanitized app name (replacing `-` and `.` with `_`)
    - If `$db_pwd` doesn't already exists, pick a random database password and store it in that setting
    - If the database doesn't exists yet, create the SQL user and DB using `ynh_mysql_create_db` or `ynh_psql_create_db`.

    ### Deprovision

    - Drop the DB using `ynh_mysql_remove_db` or `ynh_psql_remove_db`
    - Deletes the `db_name`, `db_user` and `db_pwd` settings

    ### Legacy management

    - In the past, the sql passwords may have been named `mysqlpwd` or `psqlpwd`, in which case it will automatically be renamed as `db_pwd`
    """

    # Notes for future?
    # deep_clean  -> ... idk look into any db name that would not be related to any app...
    # backup -> dump db
    # restore -> setup + inject db dump

    type = "database"
    priority = 90
    dbtype: str = ""

    default_properties: Dict[str, Any] = {
        "dbtype": None,
    }

    def __init__(self, properties: Dict[str, Any], *args, **kwargs):
        if "type" not in properties or properties["type"] not in [
            "mysql",
            "postgresql",
        ]:
            raise YunohostPackagingError(
                "Specifying the type of db ('mysql' or 'postgresql') is mandatory for db resources"
            )

        # Hack so that people can write type = "mysql/postgresql" in toml but it's loaded as dbtype
        # to avoid conflicting with the generic self.type of the resource object...
        # dunno if that's really a good idea :|
        properties = {"dbtype": properties["type"]}

        super().__init__(properties, *args, **kwargs)

    def db_exists(self, db_name):
        if self.dbtype == "mysql":
            return os.system(f"mysqlshow | grep -q -w '{db_name}' 2>/dev/null") == 0
        elif self.dbtype == "postgresql":
            return (
                os.system(
                    f"sudo --login --user=postgres psql '{db_name}' -c ';' >/dev/null 2>/dev/null"
                )
                == 0
            )
        else:
            return False

    def provision_or_update(self, context: Dict = {}):
        # This is equivalent to ynh_sanitize_dbid
        db_user = self.app.replace("-", "_").replace(".", "_")
        db_name = self.get_setting("db_name") or db_user
        self.set_setting("db_name", db_name)
        self.set_setting("db_user", db_user)

        db_pwd = None
        if self.get_setting("db_pwd"):
            db_pwd = self.get_setting("db_pwd")
        else:
            # Legacy setting migration
            legacypasswordsetting = (
                "psqlpwd" if self.dbtype == "postgresql" else "mysqlpwd"
            )
            if self.get_setting(legacypasswordsetting):
                db_pwd = self.get_setting(legacypasswordsetting)
                self.delete_setting(legacypasswordsetting)
                self.set_setting("db_pwd", db_pwd)

        if not db_pwd:
            db_pwd = random_ascii(24)
            self.set_setting("db_pwd", db_pwd)

        if not self.db_exists(db_name):
            if self.dbtype == "mysql":
                self._run_script(
                    "provision",
                    f"ynh_mysql_create_db '{db_name}' '{db_user}' '{db_pwd}'",
                )
            elif self.dbtype == "postgresql":
                self._run_script(
                    "provision",
                    f"ynh_psql_create_user '{db_user}' '{db_pwd}'; ynh_psql_create_db '{db_name}' '{db_user}'",
                )

    def deprovision(self, context: Dict = {}):
        db_user = self.app.replace("-", "_").replace(".", "_")
        db_name = self.get_setting("db_name") or db_user

        if self.dbtype == "mysql":
            db_helper_name = "mysql"
        elif self.dbtype == "postgresql":
            db_helper_name = "psql"
        else:
            raise RuntimeError(f"Invalid dbtype {self.dbtype}")

        self._run_script(
            "deprovision",
            f"""
ynh_{db_helper_name}_database_exists "{db_name}" && ynh_{db_helper_name}_drop_db "{db_name}" || true
ynh_{db_helper_name}_user_exists "{db_user}" && ynh_{db_helper_name}_drop_user "{db_user}" || true
""",
        )

        self.delete_setting("db_name")
        self.delete_setting("db_user")
        self.delete_setting("db_pwd")


class NodejsAppResource(AppResource):
    """
    Installs a nodejs version using "n" to be used by the app

    Sourcing the helpers will then automatically tweak the PATH variable such that you may call `npm` directly.

    Sourcing the helpers will also automatically define:
    - `$path_with_nodejs` to be used in the systemd config (`Environment="PATH=__PATH_WITH_NODEJS__"`)
    - `$nodejs_dir`, the directory containing the specific version of nodejs, which may be used in the systemd config too (e.g. `ExecStart=__NODEJS_DIR__/node foo bar`)

    ### Example
    ```toml
    [resources.nodejs]
    version = "18.2"
    ```

    ### Properties
    - `version`: The nodejs version needed by the app

    ### Provision/Update
    - Call "n" to install the corresponding nodejs version
    - Resolve the "actual version" installed (typically if version `20` is requested, the actual version may be `20.1.2`)
    - This "actual version" is stored as `nodejs_version` in the app settings
    - Garbage-collect unused versions

    ### Deprovision
    - Delete the `nodejs_version` setting
    - Garbage-collect unused versions
    """

    # Notes for future?
    # deep_clean  -> ... trash unused versions
    # backup -> nothing?
    # restore -> nothing/re-provision

    type = "nodejs"
    priority = 100
    version: str = ""

    default_properties: Dict[str, Any] = {
        "version": None,
    }

    N_INSTALL_DIR = "/opt/node_n"

    @property
    def n(self):
        return f"/usr/share/yunohost/helpers.v{self.helpers_version}.d/vendor/n/n"

    def installed_versions(self):
        out = check_output(f"{self.n} ls", env={"N_PREFIX": self.N_INSTALL_DIR})
        return [version.split("/")[-1] for version in out.strip().split("\n")]

    def provision_or_update(self, context: Dict = {}):
        os.makedirs(self.N_INSTALL_DIR, exist_ok=True)

        cmd = f"{self.n} install {self.version}"
        if system_arch() == "arm64":
            cmd += " --arch=arm64"

        self._run_script(
            "provision_or_update", cmd, env={"N_PREFIX": self.N_INSTALL_DIR}
        )
        matching_versions = [
            v
            for v in self.installed_versions()
            if v == self.version or v.startswith(self.version + ".")
        ]
        assert matching_versions, (
            f"Uhoh, no matching version found among {self.installed_versions()} after installing nodejs {self.version} ?"
        )
        sorted_versions = sorted(
            matching_versions, key=lambda s: list(map(int, s.split(".")))
        )
        actual_version = sorted_versions[-1]

        self.set_setting("nodejs_version", actual_version)
        self.garbage_collect_unused_versions()

    def deprovision(self, context: Dict = {}):
        self.delete_setting("nodejs_version")
        self.garbage_collect_unused_versions()

    def garbage_collect_unused_versions(self):
        from ..app import _installed_apps, app_setting

        used_versions = []
        for app in _installed_apps():
            v = app_setting(app, "nodejs_version")
            if v:
                used_versions.append(v)

        unused_versions = set(self.installed_versions()) - set(used_versions)
        if unused_versions:
            cmds = [f"{self.n} rm {version}" for version in unused_versions]
            self._run_script(
                "cleanup", "\n".join(cmds), env={"N_PREFIX": self.N_INSTALL_DIR}
            )


class RubyAppResource(AppResource):
    """
    Installs a ruby version to be used by the app, using "rbenv"

    Note that ruby is compiled on the target system, and therefore requires the following dependencies to be installed : `gcc, make, libjemalloc-dev, libffi-dev, libyaml-dev, zlib1g-dev`

    Sourcing the helpers will then automatically tweak the `PATH` variable such that you may call `ruby` and `gem` directly.

    Sourcing the helpers will also automatically define:
    - `$path_with_ruby` to be used in the systemd config (`Environment="PATH=__PATH_WITH_RUBY__"`)
    - `$ruby_dir`, the directory containing the specific version of ruby, which may be used in the systemd config too (e.g. `ExecStart=__RUBY_DIR__/ruby foo bar`)

    ### Example
    ```toml
    [resources.ruby]
    version = "3.2"
    ```

    ### Properties
    - `version`: The ruby version needed by the app

    ### Provision/Update
    - Fetch/update a copy of the rbenv tool as well as ruby-build, rbenv-aliases and xxenv-latest
    - Compute the actual "latest" version for the requested version, e.g. `3.2` may corresponds to `3.2.1`
    - This "actual version" is stored as `ruby_version` in the app settings
    - Install (compile) Ruby (may take some time)
    - Garbage-collect unused versions

    ### Deprovision
    - Delete the `ruby_version` setting
    - Garbage-collect unused versions
    """

    type = "ruby"
    priority = 100
    version: str = ""

    default_properties: Dict[str, Any] = {
        "version": None,
    }

    RBENV_ROOT = "/opt/rbenv"

    @property
    def rbenv(self):
        return f"{self.RBENV_ROOT}/bin/rbenv"

    def installed_versions(self):
        return (
            check_output(
                f"{self.rbenv} versions --bare --skip-aliases | grep -Ev '/'",
                env={"RBENV_ROOT": self.RBENV_ROOT},
            )
            .strip()
            .split("\n")
        )

    def update_rbenv(self):
        self._run_script(
            "provision_or_update",
            f"""
            _ynh_git_clone "https://github.com/rbenv/rbenv" "{self.RBENV_ROOT}"
            _ynh_git_clone "https://github.com/rbenv/ruby-build" "{self.RBENV_ROOT}/plugins/ruby-build"
            _ynh_git_clone "https://github.com/tpope/rbenv-aliases" "{self.RBENV_ROOT}/plugins/rbenv-aliase"
            _ynh_git_clone "https://github.com/momo-lab/xxenv-latest" "{self.RBENV_ROOT}/plugins/xxenv-latest"
            mkdir -p "{self.RBENV_ROOT}/cache"
            mkdir -p "{self.RBENV_ROOT}/shims"
        """,
        )

    def provision_or_update(self, context: Dict = {}):
        for package in [
            "gcc",
            "make",
            "libjemalloc-dev",
            "libffi-dev",
            "libyaml-dev",
            "zlib1g-dev",
        ]:
            if os.system(f'dpkg --list | grep -q "^ii  {package}"') != 0:
                raise YunohostPackagingError(f"{package} is required to install Ruby")

        self.update_rbenv()

        ruby_version = check_output(
            f"{self.rbenv} latest --print '{self.version}'",
            env={"RBENV_ROOT": self.RBENV_ROOT},
        )
        self.set_setting("ruby_version", ruby_version)
        logger.info(f"Building Ruby {ruby_version}, this may take some time...")
        self._run_script(
            "provision_or_update",
            f"""
            #export RBENV_ROOT='{self.RBENV_ROOT}'
            export RUBY_CONFIGURE_OPTS='--disable-install-doc --with-jemalloc'
            # Use half of available CPUs for compiling
            # The trick with 1 + ...  -1 is to prevent having '0' when there's only one CPU available.
            NB_CPU_TO_USE="$(( 1 + ($(grep -c ^processor /proc/cpuinfo) - 1) / 2 ))"
            export MAKE_OPTS="-j$(NB_CPU_TO_USE)"
            {self.rbenv} install --skip-existing '{ruby_version}' 2>&1
            if {self.rbenv} alias --list | grep --quiet '{self.app} '; then
                {self.rbenv} alias {self.app} --remove
            fi
            {self.rbenv} alias {self.app} '{ruby_version}'
        """,
        )
        self.garbage_collect_unused_versions()

    def deprovision(self, context: Dict = {}):
        self.delete_setting("ruby_version")
        self.garbage_collect_unused_versions()

    def garbage_collect_unused_versions(self):
        from ..app import _installed_apps, app_setting

        used_versions = []
        for app in _installed_apps():
            v = app_setting(app, "ruby_version")
            if v:
                used_versions.append(v)

        unused_versions = set(self.installed_versions()) - set(used_versions)
        if unused_versions:
            cmds = [
                f"{self.rbenv} uninstall --force {version}"
                for version in unused_versions
            ]
            self._run_script("cleanup", "\n".join(cmds))


class GoAppResource(AppResource):
    """
    Installs a go version to be used by the app, using "goenv"

    Sourcing the helpers will then automatically tweak the `PATH` variable such that you may call `go` directly.

    Sourcing the helpers will also automatically define:
    - `$go_dir`, the directory containing the specific version of Go

    ### Example
    ```toml
    [resources.go]
    version = "1.20"
    ```

    ### Properties
    - `version`: The go version needed by the app

    ### Provision/Update
    - Fetch/update a copy of the goenv tool and xxenv-latest
    - Compute the actual "latest" version for the requested version, e.g. `1.20` may corresponds to `1.20.2`
    - This "actual version" is stored as `go_version` in the app settings
    - Install the corresponding Go version
    - Garbage-collect unused versions

    ### Deprovision
    - Delete the `go_version` setting
    - Garbage-collect unused versions
    """

    type = "go"
    priority = 100
    version: str = ""

    default_properties: Dict[str, Any] = {
        "version": None,
    }

    GOENV_ROOT = "/opt/goenv"

    @property
    def goenv(self):
        return f"{self.GOENV_ROOT}/bin/goenv"

    @property
    def goenv_latest(self):
        return f"{self.GOENV_ROOT}/plugins/xxenv-latest/bin/goenv-latest"

    def update_goenv(self):
        self._run_script(
            "provision_or_update",
            f"""
            _ynh_git_clone https://github.com/syndbg/goenv '{self.GOENV_ROOT}'
            _ynh_git_clone https://github.com/momo-lab/xxenv-latest '{self.GOENV_ROOT}/plugins/xxenv-latest'
            mkdir -p '{self.GOENV_ROOT}/cache'
            mkdir -p '{self.GOENV_ROOT}/shims'
        """,
        )

    def provision_or_update(self, context: Dict = {}):
        self.update_goenv()
        go_version = check_output(
            f"{self.goenv_latest} --print {self.version}",
            env={
                "GOENV_ROOT": self.GOENV_ROOT,
                "PATH": self.GOENV_ROOT + "/bin/:" + os.environ["PATH"],
            },
        )
        self.set_setting("go_version", go_version)
        self._run_script(
            "provision_or_update",
            f"{self.goenv} install --quiet --skip-existing '{go_version}' 2>&1",
            env={"GOENV_ROOT": self.GOENV_ROOT},
        )
        self.garbage_collect_unused_versions()

    def deprovision(self, context: Dict = {}):
        self.delete_setting("go_version")
        self.garbage_collect_unused_versions()

    def garbage_collect_unused_versions(self):
        installed_versions = check_output(
            f"{self.goenv} versions --bare --skip-aliases",
            env={"GOENV_ROOT": self.GOENV_ROOT},
        )
        installed_versions = [
            version
            for version in installed_versions.strip().split("\n")
            if "\\" not in version
        ]

        used_versions = []
        from ..app import _installed_apps, app_setting

        for app in _installed_apps():
            v = app_setting(app, "go_version")
            if v:
                used_versions.append(v)

        unused_versions = set(installed_versions) - set(used_versions)
        if unused_versions:
            cmds = [
                f"{self.goenv} uninstall --force '{version}'"
                for version in unused_versions
            ]
            self._run_script(
                "cleanup", "\n".join(cmds), env={"GOENV_ROOT": self.GOENV_ROOT}
            )


class ComposerAppResource(AppResource):
    """
    Installs a composer version to be used by the app

    You may then use `ynh_composer_exec` in your script to run composer actions

    Note that this resource requires that the app requires an `install_dir`, and installs php dependencies via the `apt` resource.

    ### Example
    ```toml
    [resources.composer]
    version = "2.7.7"
    ```

    ### Properties
    - `version`: The composer version needed by the app

    ### Provision/Update
    - Download `composer.phar` for the corresponding version from `getcomposer.org`
    - `composer.phar` is placed in the `$install_dir` of the app
    - Define `composer_version` as the requested version

    ### Deprovision
    - Delete `composer.phar`
    - Delete the `composer_verison` setting
    """

    type = "composer"
    priority = 100
    version: str = ""

    default_properties: Dict[str, Any] = {
        "version": None,
    }

    @property
    def composer_url(self):
        return f"https://getcomposer.org/download/{self.version}/composer.phar"

    def provision_or_update(self, context: Dict = {}):
        install_dir = self.get_setting("install_dir")
        if not install_dir:
            raise YunohostPackagingError(
                "This app has no install_dir defined ? Packagers: please make sure to have the install_dir resource before composer"
            )

        if not self.get_setting("php_version"):
            raise YunohostPackagingError(
                "This app has no php_version defined ? Packagers: please make sure to install php dependencies using apt before composer"
            )

        import requests

        composer_r = requests.get(self.composer_url, timeout=30)
        assert composer_r.status_code == 200, (
            "Uhoh, failed to download {self.composer_url} ? Return code: {composer_r.status_code}"
        )

        with open(f"{install_dir}/composer.phar", "wb") as f:
            f.write(composer_r.content)
        chown(f"{install_dir}/composer.phar", self.app)

        self.set_setting("composer_version", self.version)

    def deprovision(self, context: Dict = {}):
        install_dir = self.get_setting("install_dir")

        self.delete_setting("composer_version")
        if os.path.exists(f"{install_dir}/composer.phar"):
            os.remove(f"{install_dir}/composer.phar")

AppResourceClassesByType = {c.__fields__["type"].default: c for c in AppResource.__subclasses__()}
