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
from typing import Any, Literal, Iterator, NotRequired, TypedDict
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
from yunohost.app import (
    _hydrate_app_template,
    _get_app_settings,
    _set_app_settings,
    APPS_SETTING_PATH,
)
from yunohost.service import service_reload_or_restart
from yunohost.utils.error import YunohostError
from yunohost.utils.eval import evaluate_simple_js_expression

logger = getLogger("yunohost.utils.resources")

DIR_TO_BACKUP_CONF_MANUALLY_MODIFIED = "/var/cache/yunohost/appconfbackup"

JSExpression = str
IFClause = Literal[True] | JSExpression


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


def evaluate_if_clause(if_clause, env):
    if_clause_hydrated = _hydrate_app_template(if_clause, env)
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

    # FIXME: These should be settable via the manifest ... except for type = "app" for owner/group/perms ?
    id: str
    app: str
    type: str
    content: str | None = None
    content_to_write: str | None = None
    env: dict[str, Any]
    owner: str = "root"
    group: str = "root"
    perms: str = "rw-r--r--"
    exposed: list[str] = ["template", "path"]

    @property
    def name(self):
        return self.type if self.id != "main" else f"{self.type}.{self.id}"

    def exists(self):
        return os.path.exists(self.path)

    def render(self, template_content) -> None:
        self.content = _hydrate_app_template(
            template_content, self.env, raise_exception_if_missing_var=True
        )

    def checksum(self) -> str:
        assert self.content
        return hashlib.md5(self.content.encode()).hexdigest()

    def write(self, content):
        write_to_file(self.path, content)
        chown(self.path, self.owner, self.group)
        chmod(self.path, sym_to_octal(self.perms))

    def hydrate_properties(self, template_dir: str):

        for key, value in dict(self).items():
            if isinstance(value, str):
                if (
                    key.endswith("template")
                    and not value.startswith("/")
                    and template_dir
                ):
                    value = f"{template_dir}/{value}"
                setattr(
                    self,
                    key,
                    _hydrate_app_template(
                        value,
                        {"app": self.app, "conf_id": self.id, **self.env},
                        raise_exception_if_missing_var=True,
                    ),
                )

    ###############################################################
    # The 'original' conf refers to the original configuration    #
    # as generated by YunoHost / the app templates, *before* the  #
    # admins may have possibly manually edited it, compared to    #
    # the 'current' on-disk conf.                                 #
    ###############################################################

    def original_checksum(self):
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
            raise YunohostError(f"Failed to write original conf for {self.name}? {e}")

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

    def backup_current_conf(self):

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

    def prepare(self) -> Iterator[ConfigurationAdd | ConfigurationUpdate]:

        self.render(read_file(self.template))
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


class AppConfigurationsManager:

    def __init__(self, app: str, wanted: dict, env: dict[str, str] = {}, workdir=None) -> None:
        self.app = app
        self.wanted = copy.deepcopy(wanted)
        self.workdir = workdir if workdir is not None else os.path.join(APPS_SETTING_PATH, app)
        self.env = env
        if not self.env:
            from yunohost.app import _make_environment_for_app_script
            self.env = _make_environment_for_app_script(app, workdir=workdir)

        if "configurations" not in self.wanted:
            self.wanted["configurations"] = {}

    def compute_todos(
        self,
    ) -> Iterator[
        tuple[
            Literal["add", "update", "remove"],
            str,
            str,
            BaseConfiguration | None,
            str | None,
            list[ConfigurationAdd | ConfigurationUpdate | ConfigurationRemove],
        ]
    ]:

        conf_settings = _get_app_settings(self.app).get("_configurations", {})
        current_confs: dict[tuple, str] = {
            tuple(k.split(".")): v["path"] for k, v in conf_settings.items()
        }
        wanted_confs: dict[tuple, BaseConfiguration] = {
            (c.type, c.id): c for c in self.load_wanted_confs()
        }

        for key, path in current_confs.items():
            type_, id_ = key
            if key not in wanted_confs:
                details = list(ConfigurationClassesByType[type_].prepare_rm(self.app, id_, path))
                if details:
                    yield ("remove", type_, id_, None, path, details)

        for key, conf in wanted_confs.items():
            type_, id_ = key
            if key not in current_confs:
                details = list(conf.prepare())
                if details:
                    yield ("add", type_, id_, conf, None, details)
            else:
                details = list(conf.prepare())
                if details:
                    yield ("update", type_, id_, conf, None, details)

    def format_todos_for_display(self, todos, with_diff=False) -> dict:

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
                service_reload_or_restart(services_to_reload, raise_exception_if_conf_broken=True)
            except (KeyboardInterrupt, Exception) as e:
                if isinstance(e, KeyboardInterrupt):
                    logger.error(m18n.n("operation_interrupted"))
                else:
                    logger.error(f"Failed to {todo} {name} configuration : {e}")

                if raise_exception_if_failure:
                    raise YunohostError("app_regenconf_failed", app=self.app, error=e)
                else:
                    logger.error(
                        m18n.n("app_regenconf_failed", app=self.app, error=e)
                    )

        return self.format_todos_for_display(todos, with_diff=with_diff)

    def load_wanted_confs(self) -> list[BaseConfiguration]:

        confs = []

        for type_, confs_properties in self.wanted["configurations"].items():

            confs_properties = confs_properties.copy()
            if type_ not in ConfigurationClassesByType:
                raise YunohostError(f"Unknown configuration type {type_}")

            ConfigurationClass = ConfigurationClassesByType[type_]
            exposed_properties = ConfigurationClass.__fields__["exposed"].default

            main_properties = confs_properties.pop("main", {})
            if_clause = main_properties.pop("if") if "if" in main_properties else None
            incorrect_properties = [p for p in main_properties.keys() if p not in exposed_properties]
            if incorrect_properties:
                raise YunohostError(f"Uhoh, the following properties are unknown / not exposed for configuration {type}.main: {', '.join(incorrect_properties)}", raw_msg=True)

            # Initialize the "main" conf
            if if_clause is None or evaluate_if_clause(if_clause, self.env):
                confs.append(
                    ConfigurationClass(
                        **main_properties,
                        id="main",
                        env=self.env,
                        type=type_,
                        app=self.app,
                    )
                )

            # Iterate on other confs than "main"
            for key, values in confs_properties.items():

                if not isinstance(values, dict):
                    raise YunohostError(
                        f"Uhoh, in {type_} conf properties, {key} should be associated with a dict ... (did you meant <conf_id>.{key} ?)",
                        raw_msg=True,
                    )

                incorrect_properties = [p for p in values.keys() if p not in exposed_properties]
                if incorrect_properties:
                    raise YunohostError(f"Uhoh, the following properties are unknown / not exposed for configuration {type}.{key}: {', '.join(incorrect_properties)}", raw_msg=True)
                if_clause = values.pop("if") if "if" in values else None
                if if_clause is None or evaluate_if_clause(if_clause, self.env):
                    confs.append(
                        ConfigurationClass(
                            **values,
                            id=key,
                            env=self.env,
                            type=type_,
                            app=self.app,
                        )
                    )

        template_dir = (self.workdir.rstrip("/") + "/conf/") if self.workdir else None
        for conf in confs:
            conf.hydrate_properties(template_dir=template_dir)

        return confs


class NginxConfiguration(BaseConfiguration):

    type = "nginx"

    exposed: list[str] = []

    def __init__(self, *args, **kwargs):

        # Default values for main and extras
        if kwargs["id"] == "main":
            kwargs["template"] = "nginx.conf"
            kwargs["path"] = "/etc/nginx/conf.d/__DOMAIN__.d/__APP__.conf"
        else:
            kwargs["template"] = "nginx-__CONF_ID__.conf"
            kwargs["path"] = "/etc/nginx/conf.d/__DOMAIN__.d/__APP__.d/__CONF_ID__.conf"

        super().__init__(*args, **kwargs)

    def render(self, template_content) -> None:
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




ConfigurationClassesByType = {
    c.__fields__["type"].default: c for c in BaseConfiguration.__subclasses__()
}
