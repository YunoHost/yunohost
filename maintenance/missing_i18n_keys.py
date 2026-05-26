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

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Generator

import yaml

###############################################################################
#   Find used keys in python code                                             #
###############################################################################


def find_expected_string_keys(project: Path) -> Generator[str, None, None]:
    # Try to find :
    #    m18n.n(   "foo"
    #    YunohostError("foo"
    #    YunohostValidationError("foo"
    #    # i18n: foo
    regex_m18n = re.compile(r"m18n\.n\(\n*\s*[\"\'](\w+)[\"\']")
    regex_ynherr = re.compile(r"YunohostError\(\n*\s*[\'\"](\w+)[\'\"]")
    regex_ynhxerr = re.compile(
        r"Yunohost(?:Validation|Authentication)Error\(\n*\s*[\'\"](\w+)[\'\"]"
    )
    regex_comment = re.compile(r"# i18n: [\'\"]?(\w+)[\'\"]?")

    srcdir = project / "src"
    python_files: list[Path] = [
        *srcdir.rglob("*.py"),
        *srcdir.rglob("*.py.disabled"),
        project / "bin" / "yunohost",
    ]

    for file in python_files:
        content = file.read_text()
        for regex in [regex_m18n, regex_ynherr, regex_ynhxerr, regex_comment]:
            for match in regex.findall(content):
                if not match.endswith("_"):
                    yield match

    # For each diagnosis, try to find strings like "diagnosis_stuff_foo" (c.f. diagnosis summaries)
    # Also we expect to have "diagnosis_description_<name>" for each diagnosis
    regex_diagnosis = re.compile(r"[\"\'](diagnosis_[a-z]+_\w+)[\"\']")

    diagnoser_files: list[Path] = [
        *(srcdir / "diagnosers").glob("*.py"),
        *(srcdir / "diagnosers").glob("*.py.disabled"),
    ]
    for file in diagnoser_files:
        if file.name == "__init__.py":
            continue
        content = file.read_text()
        for match in regex_diagnosis.findall(content):
            if match.endswith("_"):
                # Ignore some name fragments which are actually concatenated with other stuff..
                continue
            yield match

        name = file.name.removesuffix(".disabled").removesuffix(".py")
        yield f"diagnosis_description_{name.split('-')[-1]}"

    # For each migration, expect to find "migration_description_<name>"
    migration_files: list[Path] = [
        *(srcdir / "migrations").glob("0*.py"),
        *(srcdir / "migrations").glob("0*.py.disabled"),
    ]
    for file in migration_files:
        name = file.name.removesuffix(".disabled").removesuffix(".py")
        yield f"migration_description_{name}"

    # For each default service, expect to find "service_description_<name>"
    services_yml = project / "conf" / "yunohost" / "services.yml"
    for service, info in yaml.safe_load(services_yml.open("r")).items():
        if info is None:
            continue
        yield f"service_description_{service}"

    # For all unit operations, expect to find "log_<name>"
    # A unit operation is created either using the @is_unit_operation decorator
    # or using OperationLogger(
    for file in python_files:
        lines = iter(file.read_text().splitlines())
        for line in lines:
            if line.startswith("@is_unit_operation(") and "flash=True" not in line:
                line = next(lines)
                funcname = line.removeprefix("def ").split("(")[0]
                yield f"log_{funcname}"

    regex_logger = re.compile(r"OperationLogger\(\n*\s*[\"\'](\w+)[\"\']")
    for python_file in python_files:
        content = open(python_file).read()
        for match in regex_logger.findall(content):
            yield f"log_{match}"

    # Keys for the actionmap ...
    actionsmap_yml = project / "share" / "actionsmap.yml"
    for category in yaml.safe_load(actionsmap_yml.open("r")).values():
        if "actions" not in category.keys():
            continue
        for action in category["actions"].values():
            if "arguments" not in action.keys():
                continue
            for argument in action["arguments"].values():
                extra = argument.get("extra")
                if not extra:
                    continue
                if "password" in extra:
                    yield extra["password"]
                if "ask" in extra:
                    yield extra["ask"]
                if "comment" in extra:
                    yield extra["comment"]
                if "pattern" in extra:
                    yield extra["pattern"][1]
                if "help" in extra:
                    yield extra["help"]

    # Hardcoded expected keys ...
    yield "admin_password"  # Not sure that's actually used nowadays...

    for method in ["tar", "copy", "custom"]:
        yield "backup_applying_method_%s" % method
        yield "backup_method_%s_finished" % method

    registrar_list = project / "share" / "registrar_list.toml"
    registrars = tomllib.load(registrar_list.open("rb"))
    supported_registrars = ["ovh", "gandi", "godaddy"]
    for registrar in supported_registrars:
        for key in registrars[registrar].keys():
            yield f"domain_config_{key}"

    # Domain config panel
    domain_settings_with_help_key = [
        "portal_logo",
        "portal_public_intro",
        "portal_theme",
        "portal_user_intro",
        "search_engine",
        "custom_css",
        "dns",
        "enable_public_apps_page",
    ]
    domain_section_with_no_name = ["app", "cert_", "mail", "registrar"]
    config_domain_toml = project / "share" / "config_domain.toml"
    for panel_key, panel in tomllib.load(config_domain_toml.open("rb")).items():
        if not isinstance(panel, dict):
            continue
        yield f"domain_config_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            if section_key not in domain_section_with_no_name:
                yield f"domain_config_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict):
                    continue
                yield f"domain_config_{key}"
                if key in domain_settings_with_help_key:
                    yield f"domain_config_{key}_help"

    # App config panel
    app_settings_with_help_key = [
        "logo",
        "description",
        "force_upgrade",
    ]
    config_app_toml = project / "share" / "config_app.toml"
    for panel_key, panel in tomllib.load(config_app_toml.open("rb")).items():
        if not isinstance(panel, dict):
            continue
        yield f"app_config_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            if section_key != "permissions":
                yield f"app_config_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict) or values.get("visible") is False:
                    continue
                if section_key == "permissions":
                    key_ = f"permission_{key}"
                else:
                    key_ = key
                yield f"app_config_{key_}"
                if key in app_settings_with_help_key:
                    yield f"app_config_{key_}_help"

    # Global settings
    # Boring hard-coding because there's no simple other way idk
    settings_without_help_key = [
        "passwordless_sudo",
        "smtp_relay_host",
        "smtp_relay_password",
        "smtp_relay_port",
        "smtp_relay_user",
        "ssowat_panel_overlay_enabled",
        "root_password",
        "root_access_explain",
        "root_password_confirm",
        "tls_passthrough_explain",
        "allow_edit_email",
        "allow_edit_email_alias",
        "allow_edit_email_forward",
    ]

    config_global_toml = project / "share" / "config_global.toml"
    for panel_key, panel in tomllib.load(config_global_toml.open("rb")).items():
        if not isinstance(panel, dict):
            continue
        yield f"global_settings_setting_{panel_key}_name"
        for section_key, section in panel.items():
            if not isinstance(section, dict):
                continue
            yield f"global_settings_setting_{section_key}_name"
            for key, values in section.items():
                if not isinstance(values, dict):
                    continue
                yield f"global_settings_setting_{key}"
                if key not in settings_without_help_key:
                    yield f"global_settings_setting_{key}_help"


###############################################################################
#   Compare keys used and keys defined                                        #
###############################################################################


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", type=str, choices=["check", "fix"])
    parser.add_argument("--path", type=Path, help="Path to the project")
    args = parser.parse_args()

    project_dir: Path = args.path or Path(__file__).resolve().parent.parent
    locale_dir = project_dir / "locales"
    reference_file = locale_dir / "en.json"

    expected_string_keys = set(find_expected_string_keys(project_dir))
    keys_defined_for_en = json.load(reference_file.open("r")).keys()
    keys_defined = set(keys_defined_for_en)

    unused_keys = keys_defined.difference(expected_string_keys)
    unused_keys = sorted(unused_keys)

    undefined_keys = expected_string_keys.difference(keys_defined)
    undefined_keys = sorted(undefined_keys)

    if args.mode == "check":
        # Unused keys are not too problematic, will be automatically
        # removed by the other autoreformat script,
        # but still informative to display them
        if unused_keys:
            print("Those i18n keys appears unused:")
            for key in unused_keys:
                print(f"    - {key}")
        if undefined_keys:
            print("Those i18n keys should be defined in en.json:")
            for key in undefined_keys:
                print(f"    - {key}")
            sys.exit(1)

    if args.mode == "fix":
        data = json.load(reference_file.open("r"))
        for key in undefined_keys:
            data[key] = "FIXME"
        for key in unused_keys:
            del data[key]

        with reference_file.open("w") as reference:
            json.dump(
                data,
                reference,
                indent=4,
                ensure_ascii=False,
                sort_keys=True,
            )
            reference.write("\n")


if __name__ == "__main__":
    main()
