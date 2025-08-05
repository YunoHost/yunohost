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

import copy
import os
import base64
import hashlib
import tempfile
import subprocess
import datetime
import pwd
import re
from logging import getLogger
from typing import Any, Literal, Iterator, NotRequired, TypedDict, Callable
from pydantic import BaseModel

from moulinette import m18n
from moulinette.utils.filesystem import (
    read_file,
    write_to_file,
    chmod,
    chown,
    rm,
    mkdir,
)
from ..app import (
    _hydrate_app_template,
    _get_app_settings,
    _set_app_settings,
    APPS_SETTING_PATH,
)
from ..service import _run_service_command, service_reload_or_restart, service_add, service_remove, _get_services
from .error import YunohostError, YunohostPackagingError

logger = getLogger("yunohost.utils.configurations")

DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED = "/var/cache/yunohost/appconfbackup"


class ConfigurationAdd(TypedDict):
    path: str
    content: str


class ConfigurationUpdate(TypedDict):
    path: str
    old_path: NotRequired[str]
    diff: str
    was_manually_modified: bool
    merge_success: NotRequired[bool]
    manual_changes: NotRequired[str]
    permissions: NotRequired[str]


class ConfigurationRemove(TypedDict):
    path: str


def evaluate_if_clause(if_clause: str, env: dict[str, Any]) -> bool:
    from .eval import evaluate_simple_js_expression
    if_clause_hydrated = _hydrate_app_template(if_clause, env, raise_exception_if_missing_var=True)
    try:
        return evaluate_simple_js_expression(if_clause_hydrated, env)
    except KeyError as e:
        logger.error(f"Failed to interpret if clause « {if_clause} »")
        if re.search(r"[A-Z0-9]__\s*[=!]+\s*['\"]\w", if_clause):
            logger.error("Beware that when comparing __FOO__ to a string, __FOO__ should itself be wrapped in quotes")
        raise e


def diff(content_a: str, content_b: str) -> str:

    with tempfile.NamedTemporaryFile(
        mode="w"
    ) as file_a, tempfile.NamedTemporaryFile(mode="w") as file_b:
        file_a.write(content_a)
        file_a.flush()
        file_b.write(content_b)
        file_b.flush()
        p = subprocess.run(
            [
                "git",
                "--no-pager",
                "diff",
                "--color",
                "--no-index",
                file_a.name,
                file_b.name,
            ],
            capture_output=True,
        )

        out = p.stdout.decode().strip().split("\n")
        # [5:] is to Remove the diff header
        out = out[5:]
        # Remove the 'No newline at end of file' stuff...
        out = [l for l in out if not l.startswith("\\")]

        return "\n".join(out)


OCT_TO_SYM: dict[int, str] = {
    0: "---",
    1: "--x",
    2: "-w-",
    3: "-wx",
    4: "r--",
    5: "r-x",
    6: "rw-",
    7: "rwx",
}
SYM_TO_OCT: dict[str, int] = {v: k for k, v in OCT_TO_SYM.items()}


def sym_to_octal(sym: str) -> int:

    assert len(sym) == 9
    owner, group, other = sym[:3], sym[3:6], sym[6:]
    return (
        0o100 * SYM_TO_OCT[owner] + 0o010 * SYM_TO_OCT[group] + 0o001 * SYM_TO_OCT[other]
    )


def octal_to_sym(n: int) -> str:

    oct_perms = oct(n)[-3:]
    owner, group, other = int(oct_perms[0]), int(oct_perms[1]), int(oct_perms[2])
    return OCT_TO_SYM[owner] + OCT_TO_SYM[group] + OCT_TO_SYM[other]


def file_permissions(path: str) -> tuple[str, str, str] | None:

    if not os.path.exists(path):
        return None

    stat = os.stat(path)
    return pwd.getpwuid(stat.st_uid)[0], pwd.getpwuid(stat.st_gid)[0], octal_to_sym(stat.st_mode)


class BaseConfiguration(BaseModel):

    template: str
    path: str

    id: str
    app: str
    type: str
    content: str | None = None
    content_to_write: str | None = None
    env: dict[str, Any]
    owner: str = "root"
    group: str = "root"
    perms: str = "rw-r--r--"
    exposed_properties: list[str] = ["template", "path"]

    @classmethod
    def validate_properties_from_package(cls, **props) -> None:  # type: ignore[no-untyped-def]

        exposed_properties = cls.__fields__["exposed_properties"].default
        incorrect_properties = [k for k in props.keys() if k not in exposed_properties]
        if incorrect_properties:
            cls_type = cls.__fields__["type"].default
            raise YunohostPackagingError(f"Uhoh, the following properties are unknown / not exposed for {cls_type}-type configurations: {', '.join(incorrect_properties)}")

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        app_template_dir = kwargs.pop("app_template_dir")
        assert isinstance(app_template_dir, str)

        super().__init__(**kwargs)

        self.hydrate_properties(app_template_dir=app_template_dir)

    @property
    def name(self) -> str:
        return self.type if self.id != "main" else f"{self.type}.{self.id}"

    def exists(self) -> bool:
        return os.path.exists(self.path)

    def render(self, template_content: str) -> str:
        return _hydrate_app_template(
            template_content, self.env, raise_exception_if_missing_var=True
        )

    def checksum(self) -> str:
        assert self.content
        return hashlib.md5(self.content.encode()).hexdigest()

    def write(self, content: str) -> None:
        write_to_file(self.path, content)
        chown(self.path, self.owner, self.group)
        chmod(self.path, sym_to_octal(self.perms))

    def hydrate_properties(self, app_template_dir: str) -> None:

        def _recursive_apply(function: Callable, data: Any) -> Any:
            if isinstance(data, dict):
                return {
                    key: _recursive_apply(function, value) for key, value in data.items()
                }

            if isinstance(data, list):
                return [_recursive_apply(function, value) for value in data]

            return function(data)

        def _hydrate(value: str) -> str:
            if not isinstance(value, str):
                return value
            return _hydrate_app_template(
                value,
                {"app": self.app, "conf_id": self.id, **self.env},
                raise_exception_if_missing_var=True,
            )

        for key, value in dict(self).items():
            if isinstance(value, str):
                if (
                    key.endswith("template")
                    and not value.startswith("/")
                    and app_template_dir
                ):
                    value = f"{app_template_dir}/{value}"

            if isinstance(value, (str, list, dict)):
                setattr(self, key, _recursive_apply(_hydrate, value))

    ###############################################################
    # The 'original' conf refers to the original configuration    #
    # as generated by YunoHost / the app templates, *before* the  #
    # admins may have possibly manually edited it, compared to    #
    # the 'current' on-disk conf.                                 #
    ###############################################################

    def original_checksum(self) -> str:
        settings = _get_app_settings(self.app)
        checksum = (
            settings.get("_configurations", {})
            .get(f"{self.type}.{self.id}", {})
            .get("md5")
        )
        if not checksum:
            # Legacy way of storing checksums...
            legacy_checksum_setting_name = (
                f"checksum_{self.path.replace('/', '_').replace(' ', '_')}"
            )
            checksum = settings.get(legacy_checksum_setting_name)

        return checksum

    def original_content(self) -> str | None:

        original_checksum_ = self.original_checksum()
        if not original_checksum_:
            return None

        original_conf_file = os.path.join(
            APPS_SETTING_PATH, self.app, ".original_confs", original_checksum_
        )
        if os.path.exists(original_conf_file):
            try:
                # FIXME : should we revalidate the checksum here?
                return base64.b64decode(read_file(original_conf_file).encode()).decode()
            except Exception as e:
                logger.warning(f"Failed to read original conf for {self.name}? {e}")

        return None

    def save_new_original_content_and_checksum(self) -> None:

        assert self.content is not None

        new_checksum = self.checksum()
        original_conf_dir = os.path.join(APPS_SETTING_PATH, self.app, ".original_confs")
        original_conf_file = os.path.join(original_conf_dir, new_checksum)
        os.makedirs(original_conf_dir, exist_ok=True)
        chmod(original_conf_dir, 0o770)
        try:
            write_to_file(
                original_conf_file, base64.b64encode(self.content.encode()).decode()
            )
        except Exception as e:
            raise YunohostError(f"Failed to write original conf for {self.name}? {e}", raw_msg=True)

        app_settings = _get_app_settings(self.app)
        if "_configurations" not in app_settings:
            app_settings["_configurations"] = {}
        app_settings["_configurations"][f"{self.type}.{self.id}"] = {
            "path": self.path,
            "md5": new_checksum,
        }
        _set_app_settings(self.app, app_settings)

    ##########################################################
    # The 'current' conf refers to the current, on-disk file #
    ##########################################################
    @property
    def current_path(self) -> str | None:
        settings = _get_app_settings(self.app)
        path = (
            settings.get("_configurations", {})
            .get(f"{self.type}.{self.id}", {})
            .get("path")
        )
        if path:
            return path if os.path.exists(path) else None
        else:
            # Mostly to handle migration from packaging v2 ... is it enough though
            return self.path if os.path.exists(self.path) else None

    def current_content(self) -> str:
        current_path = self.current_path
        return read_file(current_path) if current_path else ""

    def current_checksum(self) -> str | None:
        current_content = self.current_content()
        return (
            hashlib.md5(current_content.encode()).hexdigest()
            if current_content
            else None
        )

    def current_perms(self) -> tuple[str, str, str] | None:
        return file_permissions(self.current_path) if self.current_path else None

    def backup_current_conf(self) -> None:

        current_path = self.current_path
        if not current_path:
            logger.warning(
                f"Configuration {self.path} doesn't exists and therefore won't be backedup?"
            )
            return

        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_file = f"{DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED}/{self.app}/{self.path}.backup.{timestamp}"
        mkdir(os.path.dirname(backup_file), mode=0o700, parents=True, uid="root")
        write_to_file(backup_file, self.current_content())

        # FIXME : i18n
        logger.warning(
            f"Configuration {current_path} was manually modified since the installation or last upgrade. "
            f"It has been backedup in {backup_file}"
        )

    ##########################################################

    def was_manually_modified(self) -> bool:
        if self.current_path:
            if self.original_checksum() is None:
                return False
            else:
                return self.current_checksum() != self.original_checksum()
        else:
            return False

    def attempt_merge(self) -> tuple[bool, str]:
        new_c = self.content
        original_c = self.original_content()
        current_c = self.current_content()
        assert new_c is not None
        assert original_c is not None
        assert current_c is not None

        with tempfile.NamedTemporaryFile(
            mode="w"
        ) as new_f, tempfile.NamedTemporaryFile(
            mode="w"
        ) as original_f, tempfile.NamedTemporaryFile(
            mode="w"
        ) as current_f:
            new_f.write(new_c)
            new_f.flush()
            original_f.write(original_c)
            original_f.flush()
            current_f.write(current_c)
            current_f.flush()
            p = subprocess.run(
                [
                    "git",
                    "merge-file",
                    "-p",
                    "--zdiff3",
                    "-L",
                    "current_config",
                    "-L",
                    "original_config",
                    "-L",
                    "new_config",
                    current_f.name,
                    original_f.name,
                    new_f.name,
                ],
                capture_output=True,
            )
            merged_content = p.stdout.decode()

        return (p.returncode == 0, merged_content)

    def template_content(self) -> str:

        return read_file(self.template)

    def prepare(self) -> Iterator[ConfigurationAdd | ConfigurationUpdate]:

        self.content = self.render(self.template_content())
        assert self.content

        was_manually_modified = self.was_manually_modified()
        content_to_write = self.content
        merge_success = None
        if was_manually_modified:
            merge_success, merged_content = self.attempt_merge()

            if merge_success:

                # FIXME : hmmmm when / how should be display those exactly

                # FIXME: i18n
                # logger.info(
                #     f"Configuration {self.current_path} appears to have been manually modified. "
                #     "YunoHost was able to automatically merge your changes with the new configuration."
                # )
                assert merged_content
                content_to_write = merged_content
            else:

                # FIXME : hmmmm when / how should be display those exactly

                # original_content = self.original_content()
                # current_content = self.current_content()
                # assert original_content is not None
                # assert current_content is not None

                # original_vs_current_diff = diff(original_content, current_content)
                # FIXME: i18n
                # logger.warning(
                #     f"Configuration {self.current_path} appears to have been manually modified. "
                #     "YunoHost was unable to automatically merge your changes with the new configuration. "
                #     "It will therefore instead backup the current configuration and apply the new configuration. "
                #     "You may want to manually re-apply your changes:\n"
                #     f"{'#'*16}\n{original_vs_current_diff}\n{'#'*16}"
                # )
                pass

        self.content_to_write = content_to_write

        if self.current_path is None:
            yield ConfigurationAdd(path=self.path, content=self.content_to_write)
        else:
            current_content = self.current_content()
            # FIXME: there's a possible edge case where we think the current conf exists but was actually deleted...?
            assert current_content is not None

            current_perms = self.current_perms()
            perms = (self.owner, self.group, self.perms)

            if (current_content, self.current_path, current_perms) == (self.content_to_write, self.path, perms):
                # Not returning anything about confs that are up to date
                return

            configuration_update = ConfigurationUpdate(
                path=self.path,
                diff="\n" + diff(current_content, self.content_to_write),
                was_manually_modified=was_manually_modified,
            )

            if current_perms != perms:
                configuration_update["permissions"] = f"{current_perms} -> {perms}"

            if self.current_path != self.path:
                configuration_update["old_path"] = self.current_path

            if was_manually_modified:
                original_content = self.original_content()
                assert original_content is not None
                configuration_update["manual_changes"] = diff(original_content, current_content)
                assert merge_success is not None
                configuration_update["merge_success"] = merge_success

            yield configuration_update

    def apply(self) -> Iterator[str]:

        # Trick to make it explicit that this is a generator
        # even though 'yield' is only used in children class overrides
        yield from []

        if self.was_manually_modified():
            self.backup_current_conf()

        current_path = self.current_path
        if current_path and current_path != self.path:
            logger.debug(
                f"Removing old conf {current_path} since new conf is now at {self.path}"
            )
            rm(current_path)
        self.save_new_original_content_and_checksum()
        assert self.content_to_write
        self.write(self.content_to_write)

    @classmethod
    def prepare_rm(cls, app: str, id: str, path: str) -> Iterator[ConfigurationRemove]:

        if os.path.exists(path):
            yield ConfigurationRemove(path=path)

    @classmethod
    def rm(cls, app: str, id: str, path: str) -> Iterator[str]:

        # Trick to make it explicit that this is a generator
        # even though 'yield' is only used in children class overrides
        yield from []

        type_ = cls.__fields__["type"].default
        name = f"{type_}.{id}"

        if os.path.exists(path):
            logger.debug(f"Removing {name} configuration ({path})")
            rm(path)
        else:
            logger.warning(f"Configuration {name}: {path} is already absent")
            return

        app_settings = _get_app_settings(app)
        if "_configurations" not in app_settings:
            app_settings["_configurations"] = {}
        if f"{type_}.{id}" in app_settings["_configurations"]:
            del app_settings["_configurations"][f"{type_}.{id}"]
            _set_app_settings(app, app_settings)


ConfigurationTodo = \
    tuple[Literal["add"], str, str, BaseConfiguration, None, list[ConfigurationAdd | ConfigurationUpdate]] | \
    tuple[Literal["update"], str, str, BaseConfiguration, None, list[ConfigurationAdd | ConfigurationUpdate]] | \
    tuple[Literal["remove"], str, str, None, str, list[ConfigurationRemove]]


class AppConfigurationsManager:

    def __init__(self, app: str, wanted: dict, env: dict[str, str] = {}, workdir: str | None = None) -> None:
        self.app = app
        self.wanted = copy.deepcopy(wanted)
        self.workdir = workdir if workdir is not None else os.path.join(APPS_SETTING_PATH, app)
        self.env = env
        if not self.env:
            from ..app import _make_environment_for_app_script
            self.env = _make_environment_for_app_script(app, workdir=workdir)

        if "configurations" not in self.wanted:
            self.wanted["configurations"] = {}

    def compute_todos(self) -> Iterator[ConfigurationTodo]:

        conf_settings = _get_app_settings(self.app).get("_configurations", {})
        current_confs: dict[tuple[str, str], str] = {
            tuple(k.split(".")): v["path"] for k, v in conf_settings.items()
        }
        wanted_confs: dict[tuple[str, str], BaseConfiguration] = {
            (c.type, c.id): c for c in self.load_wanted_confs()
        }

        for key, path in current_confs.items():
            type_, id_ = key
            if key not in wanted_confs:
                details_rm = list(ConfigurationClassesByType[type_].prepare_rm(self.app, id_, path))
                if details_rm:
                    yield ("remove", type_, id_, None, path, details_rm)

        for key, conf in wanted_confs.items():
            type_, id_ = key
            details = list(conf.prepare())
            if details:
                if key not in current_confs:
                    yield ("add", type_, id_, conf, None, details)
                else:
                    yield ("update", type_, id_, conf, None, details)

    def format_todos_for_display(self, todos: list[ConfigurationTodo], with_diff: bool = False) -> dict:

        todos_to_display: dict[str, list[dict[str, Any]]] = {}
        for todo, type_, id_, new, path_to_remove, details in todos:

            to_display = todos_to_display[f"{type_}.{id_}"] = []

            for detail in details:

                detail_to_display: dict = {"action": todo, **dict(detail.copy())}

                if detail_to_display.get("was_manually_modified") is False:
                    del detail_to_display["was_manually_modified"]

                if "diff" in detail_to_display and not detail_to_display["diff"].strip():
                    del detail_to_display["diff"]

                if not with_diff:
                    if todo == "add":
                        del detail_to_display["content"]
                    elif todo == "update":
                        if "diff" in detail_to_display:
                            del detail_to_display["diff"]
                        if "manual_changes" in detail_to_display:
                            del detail_to_display["manual_changes"]
                    # FIXME: maybe we want to handle the content for remove as well?

                to_display.append(detail_to_display)

        return todos_to_display

    def dry_run(self, with_diff: bool = False) -> dict:
        todos = list(self.compute_todos())
        return self.format_todos_for_display(todos, with_diff=with_diff)

    def apply(self, raise_exception_if_failure: bool = True, with_diff: bool = False) -> dict:
        todos = list(self.compute_todos())
        for todo, type_, id_, new, path_to_remove, _ in todos:
            name = type_ if id_ == "main" else f"{type_}.{id_}"
            try:
                if todo == "remove":
                    assert path_to_remove
                    logger.info(f"Removing {name} configuration...")
                    g = ConfigurationClassesByType[type_].rm(self.app, id_, path_to_remove)
                elif todo == "add":
                    assert new
                    logger.info(f"Adding {name} configuration...")
                    g = new.apply()
                elif todo == "update":
                    assert new
                    logger.info(f"Updating {name} configuration...")
                    g = new.apply()
                services_to_reload = list(g)
                # NB: service_reload_or_restart also checks the conf (if there's a test_conf for that service)
                service_reload_or_restart(services_to_reload, raise_exception_if_conf_broken=True)
            except (KeyboardInterrupt, Exception) as e:
                if isinstance(e, KeyboardInterrupt):
                    logger.error(m18n.n("operation_interrupted"))
                elif not isinstance(e, YunohostError):
                    import traceback
                    stacktrace = traceback.format_exc()
                    logger.error(f"Failed to {todo} {name} configuration:\n {stacktrace}")
                else:
                    logger.error(f"Failed to {todo} {name} configuration: {e}")

                if raise_exception_if_failure:
                    raise YunohostError("app_regenconf_failed", app=self.app, error=e)
                else:
                    logger.error(
                        m18n.n("app_regenconf_failed", app=self.app, error=e)
                    )

        return self.format_todos_for_display(todos, with_diff=with_diff)

    def load_wanted_confs(self) -> Iterator[BaseConfiguration]:

        app_template_dir = (self.workdir.rstrip("/") + "/conf/") if self.workdir else None

        for type_, confs_properties in self.wanted["configurations"].items():

            confs_properties = confs_properties.copy()
            if type_ not in ConfigurationClassesByType:
                raise YunohostPackagingError(f"Unknown configuration type {type_}")

            ConfigurationClass = ConfigurationClassesByType[type_]

            # Make sure we have a "main" property and that it's first in the list
            confs_properties = {"main": confs_properties.pop("main", {}), **confs_properties}

            # Iterate on other confs than "main"
            for key, values in confs_properties.items():

                if not isinstance(values, dict):
                    raise YunohostPackagingError(
                        f"Uhoh, in {type_} conf properties, {key} should be associated with a dict ... (did you meant <conf_id>.{key} ?)"
                    )

                if_clause = values.pop("if") if "if" in values else None
                if if_clause is not None and not evaluate_if_clause(if_clause, self.env):
                    logger.debug(f"Skipping conf {type_}.{key} because 'if' clause is not met")
                    continue

                logger.debug(f"Loading conf {type_}.{key}")
                ConfigurationClass.validate_properties_from_package(**values)
                yield ConfigurationClass(
                    **values,
                    id=key,
                    env=self.env,
                    type=type_,
                    app=self.app,
                    app_template_dir=app_template_dir,
                )

                # Boring trick for fail2ban which is actually 2 file conf (filter and jail)
                # so we create one with the same inputs for main, but with id "jail" that will use a different template/path
                if type_ == "fail2ban" and key == "main":
                    assert "jail" not in confs_properties.keys(), "Can't explicitly add properties for the 'jail' part of fail2ban, just set them via the main one"
                    yield ConfigurationClass(
                        **values,
                        id="jail",
                        env=self.env,
                        type=type_,
                        app=self.app,
                        app_template_dir=app_template_dir,
                    )


class NginxConfiguration(BaseConfiguration):

    type = "nginx"

    exposed_properties: list[str] = []

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        # Default values for main and extras
        if kwargs["id"] == "main":
            kwargs["template"] = "nginx.conf"
            kwargs["path"] = "/etc/nginx/conf.d/__DOMAIN__.d/__APP__.conf"
        else:
            kwargs["template"] = "nginx-__CONF_ID__.conf"
            kwargs["path"] = "/etc/nginx/conf.d/__DOMAIN__.d/__APP__.d/__CONF_ID__.conf"

        super().__init__(**kwargs)

    def render(self, template_content: str) -> str:
        if "path" in self.env:
            path = self.env["path"].strip()
            if path != "/":
                template_content = template_content.replace("#sub_path_only", "")
            else:
                template_content = template_content.replace("#root_path_only", "")
                template_content = template_content.replace("__PATH__/", "/")

        return super().render(template_content)

    def apply(self) -> Iterator[str]:

        old_path = self.current_path if self.current_path else None
        old_parent_dir = os.path.dirname(old_path) if old_path else None

        new_path = self.path
        parent_dir = os.path.dirname(new_path)

        # Create the .d parent dir if needed
        if self.id != "main" and parent_dir.endswith(f"/{self.app}.d") and not os.path.isdir(parent_dir):
            os.makedirs(parent_dir)

        yield from super().apply()

        # Remove the old .d conf if it's now empty (for example after renaming the confs after changing the domain)
        if self.id != "main" and old_parent_dir and old_parent_dir.endswith(f"/{self.app}.d") and os.path.isdir(old_parent_dir) and len(os.listdir(parent_dir)) == 0:
            logger.debug(f"Removing {old_parent_dir}")
            rm(old_parent_dir, recursive=True)

        # Nginx should be reloaded after this
        yield "nginx"

    @classmethod
    def rm(cls, app: str, id: str, path: str) -> Iterator[str]:

        yield from super().rm(app, id, path)

        # If we just removed the last file in the $app.d directory?
        parent_dir = os.path.dirname(path)
        if id != "main" and parent_dir.endswith(f"/{app}.d") and os.path.isdir(parent_dir) and len(os.listdir(parent_dir)) == 0:
            logger.debug(f"Removing {parent_dir}")
            rm(parent_dir, recursive=True)

        # Nginx should be reloaded after this
        yield "nginx"


class PHPConfiguration(BaseConfiguration):

    type = "php"

    template = "/usr/share/yunohost/conf/php/template.conf.j2"
    extra_template: str = "extra_php-fpm.conf"  # It's optional and just appended to the base template
    path: str = "/etc/php/__PHP_VERSION__/fpm/pool.d/__APP__.conf"

    php_group: str = "__APP__"
    php_upload_max_filesize: str = "50M"
    php_memory_limit: str = "128M"
    php_process_management: Literal["ondemand", "dynamic", "static"] = "ondemand"
    php_max_children: int  # defaults to `_default_php_max_children`

    exposed_properties: list[str] = ["php_group", "php_process_management", "php_memory_limit", "php_upload_max_filesize"]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        assert kwargs["id"] == "main", "Extra php configurations are not supported"
        kwargs["php_max_children"] = PHPConfiguration._default_php_max_children()
        super().__init__(**kwargs)

    def render(self, template_content: str) -> str:

        self.env = self.env.copy()
        for prop in ["php_group", "php_process_management", "php_memory_limit", "php_upload_max_filesize", "php_max_children"]:
            if prop not in self.env:
                self.env[prop] = getattr(self, prop)

        if os.path.exists(self.extra_template):
            template_content += "\n\n" + read_file(self.extra_template)

        return super().render(template_content)

    @staticmethod
    def _default_php_max_children() -> int:

        from .system import ram_total

        total_vm, total_swap = ram_total()
        total_ram_in_MB = (total_vm + total_swap) / (1024 * 1024)

        # The value of pm.max_children is the total amount of ram divided by 2,
        # divided again by 20MB (= a default, classic worker footprint) This is
        # designed such that if PHP-FPM start the maximum of children, it won't
        # exceed half of the ram.
        php_max_children = total_ram_in_MB / 40
        cpu_count = os.cpu_count()
        assert cpu_count
        # Make sure we get at least max_children = 1
        if php_max_children <= 0:
            php_max_children = 1
        # To not overload the proc, limit the number of children to 4 times the number of cores.
        elif php_max_children > 4 * cpu_count:
            php_max_children = 4 * cpu_count

        return php_max_children

    def apply(self) -> Iterator[str]:

        assert self.path.startswith("/etc/php/")
        php_version = self.path.split("/")[3]
        # Restart php-fpm after applying the conf
        yield f"php{php_version}-fpm"

        old_path = self.current_path if self.current_path else None
        if old_path:
            assert old_path.startswith("/etc/php/")
            previous_php_version = old_path.split("/")[3]
            # Also restart the previous php-fpm version (eg if we changed the php version)
            if previous_php_version != php_version:
                yield f"php{previous_php_version}-fpm"

        yield from super().apply()

    @classmethod
    def rm(cls, app: str, id: str, path: str) -> Iterator[str]:

        assert path.startswith("/etc/php/")
        php_version = path.split("/")[3]
        # Restart php-fpm after applying the conf
        yield f"php{php_version}-fpm"

        yield from super().rm(app, id, path)


class SystemdConfiguration(BaseConfiguration):

    type = "systemd"

    # FIXME : hmmm we should probably support the usecase where the service is setup externally (typically from a .deb?)
    # and we don't want to actually handle the conf but we may want to integrate in yunohost

    # FIXME : standardize the logging stuff ?

    # FIXME : maybe study how we could simplify the writing of the conf

    # FIXME : provide a __DESCRIPTION__ to autofill the descr using the manifest ? idk

    # FIXME : look into hardening the conf, maybe provide a __STANDARD_CAPABILITIES__ stuff idk

    service_name: str
    auto: bool = True
    wait_until: str | None = None
    wait_until_stopped: str | None = None
    integrate_in_yunohost: bool = True
    main_log: str | None = None  # Oooooor should it be a dir from the log_dir resource ooooor idk
    test_status: str | None = None
    needs_exposed_ports: str | int | list[str | int] | None = None
    needs_lock: bool = False

    exposed_properties: list[str] = [
        "auto",
        "wait_until",
        "wait_until_stopped",
        "integrate_in_yunohost",
        "main_log",
        "test_status",
        "needs_exposed_ports",
        "needs_lock"
    ]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        # Default values for main and extras
        if kwargs["id"] == "main":
            kwargs["service_name"] = "__APP__"
            kwargs["template"] = "systemd.service"
            kwargs["path"] = "/etc/systemd/system/__APP__.service"
        else:
            kwargs["service_name"] = "__APP__-__CONF_ID__"
            kwargs["template"] = "systemd-__CONF_ID__.service"
            kwargs["path"] = "/etc/systemd/system/__APP__-__CONF_ID__.service"

        super().__init__(**kwargs)

    def apply(self) -> Iterator[str]:

        yield from super().apply()

        os.system("systemctl daemon-reload")
        _run_service_command("enable", self.service_name)

        needs_exposed_ports: list[int]
        if isinstance(self.needs_exposed_ports, int):
            needs_exposed_ports = [self.needs_exposed_ports]
        elif isinstance(self.needs_exposed_ports, str) and self.needs_exposed_ports.strip():
            needs_exposed_ports = [int(self.needs_exposed_ports.strip())]
        elif self.needs_exposed_ports:
            needs_exposed_ports = [int(p) for p in self.needs_exposed_ports if isinstance(p, int) or p.strip()]
        else:
            needs_exposed_ports = []

        # integrate/disintegrate the service in yunohost
        # FIXME : we should store the 'wait until' infos for later use probably
        if self.integrate_in_yunohost:
            service_add(
                self.service_name,
                log=self.main_log,
                test_status=self.test_status,
                needs_exposed_ports=needs_exposed_ports,
                need_lock=self.needs_lock
            )
        elif self.service_name in _get_services():
            service_remove(self.service_name)

        if self.auto:
            self.start()

    @classmethod
    def rm(cls, app: str, id: str, path: str) -> Iterator[str]:

        assert path.startswith("/etc/systemd/system/")
        service_name = path.split("/")[-1].split(".")[0]

        if os.system(f"systemctl --quiet is-active '{service_name}'") == 0:
            _run_service_command("stop", service_name)
        if os.system(f"systemctl --quiet is-enabled '{service_name}'") == 0:
            _run_service_command("disable", service_name)

        # Remove integration in YunoHost if it's there
        if service_name in _get_services():
            service_remove(service_name)

        yield from super().rm(app, id, path)

        os.system("systemctl daemon-reload")

    def start(self) -> None:

        if self.wait_until:
            wait_until_args = {
                "wait_until_pattern": self.wait_until,
                "log_to_watch": self.main_log or "journalctl"
            }
        else:
            wait_until_args = {}

        success = _run_service_command("restart", self.service_name, **wait_until_args)  # type: ignore[arg-type]
        if success:
            logger.info(f"Service {self.service_name} started")
        elif os.system(f"systemctl --quiet is-active {self.service_name}") == 0:
            # "Mixed" success ... service is active but did not find the wait_until pattern
            logger.warning(f"Service {self.service_name} may not be fully started yet ... (did not find pattern '{self.wait_until}' in its logs)")
        else:
            raise YunohostError(f"Service {self.service_name} failed to start")


class Fail2banConfiguration(BaseConfiguration):

    type = "fail2ban"

    log_to_watch: str
    auth_route: str | None = None  # NB: relative to the app, NOT prefixed with __PATH__ (or should it be the other way around ?)
    fail_regex: str | None = None

    exposed_properties: list[str] = ["template", "log_to_watch", "auth_route", "fail_regex"]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        assert kwargs["id"] in ["main", "jail"], "Having several fail2ban configuration per app is not supported for now"

        n_keys = len([key for key in ["template", "auth_route", "fail_regex"] if key in kwargs])
        if n_keys == 0:
            raise YunohostPackagingError("Packager: you should define either 'auth_route' or 'fail_regex' in the fail2ban conf properties. Or a custom 'template' to use.")
        elif n_keys > 1:
            raise YunohostPackagingError("Packager: 'template', 'auth_route' and 'fail_regex' can't be used simulatenously in fail2ban conf properties. Choose exactly one!")

        if "auth_route" in kwargs:
            kwargs["log_to_watch"] = "/var/log/nginx/__DOMAIN__-access.log"

        # Template/path values for main (=filter) and jail
        if kwargs["id"] == "main":
            if "template" not in kwargs:
                kwargs["template"] = "/usr/share/yunohost/conf/fail2ban/app-filter.conf.j2"
            kwargs["path"] = "/etc/fail2ban/filter.d/__APP__.conf"
        else:
            kwargs["template"] = "/usr/share/yunohost/conf/fail2ban/app-jail.conf.j2"
            kwargs["path"] = "/etc/fail2ban/jail.d/__APP__.conf"

        super().__init__(**kwargs)

    def render(self, template_content: str) -> str:

        settings = _get_app_settings(self.app)
        self.env = self.env.copy()
        self.env["enabled"] = settings.get("f2b_enabled", True)
        self.env["max_retry"] = settings.get("f2b_max_retry", 5)
        for prop in ["log_to_watch", "auth_route", "fail_regex"]:
            self.env[prop] = getattr(self, prop)

        return super().render(template_content)

    def apply(self) -> Iterator[str]:

        if not os.path.isfile(self.log_to_watch):
            raise YunohostPackagingError(f"Logfile for fail2ban {self.log_to_watch} doesn't exists (yet?), but it is necessary that this file exists for fail2ban to start")

        yield from super().apply()

        # FIXME : hmm that means fail2ban is restarted twice (once after applying the main conf=filter and after jail conf)
        # we should really "group by" the todos per type in the manager stuff
        yield "fail2ban"

    @classmethod
    def rm(cls, app: str, id: str, path: str) -> Iterator[str]:

        yield from super().rm(app, id, path)

        yield "fail2ban"


class CronConfiguration(BaseConfiguration):

    type = "cron"

    # FIXME : support either a template or specifying timing / user / command via properties ?
    # if we auto-generate the cron file, maybe auto-cd to __INSTALL_DIR__ an look at other trick to simplify syntax

    user: str = "__APP__"
    command: str = ""
    timing: str = ""
    workdir: str = "__INSTALL_DIR__"

    exposed_properties: list[str] = ["user", "command", "timing", "workdir"]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        kwargs["path"] = "/etc/cron.d/__APP__" if kwargs["id"] == "main" else "/etc/cron.d/__APP__-__CONF_ID__"

        if "command" in kwargs and "timing" in kwargs:
            if "template" in kwargs:
                raise YunohostPackagingError("Packager: you can't specify a template file when using 'command' and 'timing' for cron configurations")
            kwargs["template"] = "/dev/null"  # See method template_content()
            if "user" not in kwargs:
                kwargs["user"] = "__APP__"
            if not kwargs["timing"].startswith("@") and len(kwargs["timing"].split()) != 5:
                raise YunohostPackagingError("Packager: it sounds like property 'timing' has an incorrect format")
        else:
            if any(f in kwargs for f in ["user", "command", "timing", "workdir"]):
                raise YunohostPackagingError("Packager: you can't specify any 'command' / 'timing' / 'user' / 'workdir' property when using template mode for cron configurations")
            kwargs["template"] = "cron" if kwargs["id"] == "main" else "cron-__CONF_ID__"

        super().__init__(**kwargs)

    def template_content(self) -> str:

        if self.template == "/dev/null":
            return f"{self.timing} {self.user} cd '{self.workdir}' && {self.command}"

        # Rough check of the cron syntax, because apparently forgetting to specify the user is a common mistake
        # lines starting with '*' or a digit should have the user __APP__ or root in 6th column
        faulty_lines = subprocess.check_output(["awk", r'/^\s*\*/ || /^\s*[0-9]/ {if (($6 != "__APP__") && ($6 != "root")) print }', self.template]).decode().split("\n")
        # lines starting @ should have the user __APP__ or root in 2nd column
        faulty_lines += subprocess.check_output(["awk", r'/^\s*@/ {if (($2 != "__APP__") && ($2 != "root")) print }', self.template]).decode().split("\n")
        faulty_lines = [line for line in faulty_lines if line.strip()]
        if faulty_lines:
            faulty_lines_joined = '\n'.join(faulty_lines)
            raise YunohostPackagingError(f"Packager: it looks like your cron template is faulty ? The 'user' part should be __APP__ or root. Faulty lines:\n{faulty_lines_joined}")

        return read_file(self.template)

    def render(self, template_content: str) -> str:
        # Trick to be able to use __PHP__ to simplify the cron syntax
        if "php_version" in self.env:
            self.env = self.env.copy()
            self.env["php"] = f"/usr/bin/php{self.env['php_version']}"
        return super().render(template_content)


class SudoersConfiguration(BaseConfiguration):

    type = "sudoers"

    perms: str = "r--r-----"
    template: str = "/dev/null"  # Not used, cf self.template_content()
    # FIXME : ideally we should validate that every command is owned by root and not writable by a non-root user ...
    commands: list[str] = []

    exposed_properties: list[str] = ["commands"]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        # Default values for main and extras
        if kwargs["id"] == "main":
            kwargs["path"] = "/etc/sudoers.d/__APP__"
        else:
            kwargs["path"] = "/etc/sudoers.d/__APP__-__CONF_ID__"

        if "commands" in kwargs:
            assert not any("," in command for command in kwargs["commands"]), "sudoers 'commands' arg is supposed to be a list of commands. The individual commands are not supposed to contain ','"

        super().__init__(**kwargs)

    def template_content(self) -> str:
        return """
{% for command in commands %}
__APP__ ALL = (root) NOPASSWD: {{command}}
{%- endfor %}
        """

    def render(self, template_content: str) -> str:
        self.env = self.env.copy()
        self.env["commands"] = self.commands
        return super().render(template_content)

    def apply(self) -> Iterator[str]:
        yield from super().apply()

        # Validate logrotate conf
        p = subprocess.Popen(
            ["visudo", "-c"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, _ = p.communicate()
        if p.returncode != 0:
            errors = out.decode().strip()
            raise YunohostPackagingError(f"Uhoh, sudoers conf is not valid ?\n\n{errors}")


class LogrotateConfiguration(BaseConfiguration):

    type = "logrotate"

    template: str = "/usr/share/yunohost/conf/logrotate/template.conf.j2"
    path: str = "/etc/logrotate.d/__APP__"
    logs: list[str] = ["__LOG_DIR__/*.log"]

    exposed_properties: list[str] = ["logs"]

    # FIXME : the lograte helper did apply some chown / chmod ...
    # but i suppose it should rather be handled by the upcoming log_dir resource ?

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        assert kwargs["id"] == "main", "Only having a 'main' logrotate conf is supported"

        super().__init__(**kwargs)

    def render(self, template_content: str) -> str:

        self.env = self.env.copy()
        self.env["log_globs"] = ' '.join(self.logs)

        return super().render(template_content)

    def apply(self) -> Iterator[str]:
        yield from super().apply()

        # Validate logrotate conf
        p = subprocess.Popen(
            ["logrotate", "-d", self.path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out, _ = p.communicate()
        if p.returncode != 0:
            errors = out.decode().strip()
            raise YunohostPackagingError(f"Uhoh, logrotate conf is not valid ?\n\n{errors}")


class AppConfiguration(BaseConfiguration):

    type = "app"
    perms: str = "r--------"

    # FIXME / TODO : in many cases we can expect the app config
    # to be related to the app service (or php fpm service) and
    # maybe we want to auto-restart the service (or php fpm) when
    # it's updated ? (There's some overlap with this and the config panel mechanism)

    exposed_properties: list[str] = ["path", "template", "owner", "group", "perms"]

    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]

        app = kwargs["app"]

        assert "path" in kwargs, "Property 'path' is mandatory for 'app' configurations"

        if not kwargs["path"].startswith("/"):
            kwargs["path"] = "__INSTALL_DIR__/" + kwargs["path"]
        elif kwargs["path"].startswith(f"/etc/{app}"):
            logger.warning(f"Packagers, please use /etc/__APP__ instead of /etc/{app} when definining the path configuration")
        elif kwargs["path"].startswith(f"/home/yunohost.app/{app}"):
            logger.warning(f"Packagers, please use __DATA_DIR__ instead of /home/yunohost.app/{app} when definining the path configuration")

        if "group" in kwargs and "perms" not in kwargs:
            logger.warning(f"Packagers, in the app '{kwargs['id']}' configuration, specifying 'group' without changing the 'perms' is probably irrelevant because the default perms are 'r--------'. (In most cases, config files are only read by the app and it shouldnt be necessary to expose them to other users?)")

        classic_app_conf_dirs = [
            "__INSTALL_DIR__",
            "__DATA_DIR__",
            "/etc/__APP__",
            "/var/lib/__APP__",
            "/usr/share/__APP__"
        ]
        probably_app_conf = any(kwargs["path"].startswith(d) for d in classic_app_conf_dirs)
        if "owner" not in kwargs and probably_app_conf:
            kwargs["owner"] = app
        if "group" not in kwargs and probably_app_conf:
            kwargs["group"] = app

        super().__init__(**kwargs)


ConfigurationClassesByType = {
    c.__fields__["type"].default: c for c in BaseConfiguration.__subclasses__()
}
