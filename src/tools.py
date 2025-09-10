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

import os
import pwd
import re
import subprocess
import time
from importlib import import_module
from logging import getLogger
from typing import TYPE_CHECKING, Any, Callable, Literal, cast

from moulinette import Moulinette, m18n
from packaging import version
from typing_extensions import TypedDict

from .log import OperationLogger, is_unit_operation
from .utils.error import YunohostError, YunohostValidationError
from .utils.file_utils import chown, cp, mkdir, read_yaml, rm, write_to_yaml
from .utils.process import call_async_output
from .utils.system import (
    _apt_log_line_is_relevant,
    _dump_sources_list,
    _group_packages_per_categories,
    _list_upgradable_apt_packages,
    dpkg_is_broken,
    dpkg_lock_available,
    ynh_packages_version,
)

if TYPE_CHECKING:
    from .app import AppInfo

MIGRATIONS_STATE_PATH = "/etc/yunohost/migrations.yaml"

if TYPE_CHECKING:
    from .utils.logging import YunohostLogger

    logger = cast(YunohostLogger, getLogger("yunohost.tools"))
else:
    logger = getLogger("yunohost.tools")


def tools_versions() -> dict[str, dict[str, str]]:
    return ynh_packages_version()


def tools_rootpw(new_password: str, check_strength: bool = True) -> None:
    from .utils.password import (
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    assert_password_is_compatible(new_password)
    if check_strength:
        assert_password_is_strong_enough("admin", new_password)

    proc = subprocess.run(
        ["passwd"],
        input=f"{new_password}\n{new_password}\n".encode("utf-8"),
        capture_output=True,
    )

    if proc.returncode == 0:
        logger.info(m18n.n("root_password_changed"))
    else:
        logger.warning(proc.stdout)
        logger.warning(proc.stderr)
        logger.warning(m18n.n("root_password_desynchronized"))


def tools_maindomain(new_main_domain: str | None = None) -> dict[str, str] | None:
    from .domain import domain_main_domain

    logger.warning(
        m18n.g(
            "deprecated_command_alias",
            prog="yunohost",
            old="tools maindomain",
            new="domain main-domain",
        )
    )
    return domain_main_domain(new_main_domain=new_main_domain)


def _set_hostname(hostname: str, pretty_hostname: str | None = None) -> None:
    """
    Change the machine hostname using hostnamectl
    """

    if not pretty_hostname:
        pretty_hostname = f"(YunoHost/{hostname})"

    # First clear nsswitch cache for hosts to make sure hostname is resolved...
    subprocess.call(["nscd", "-i", "hosts"])

    # Then call hostnamectl
    commands = [
        "hostnamectl --static    set-hostname".split() + [hostname],
        "hostnamectl --transient set-hostname".split() + [hostname],
        "hostnamectl --pretty    set-hostname".split() + [pretty_hostname],
    ]

    for command in commands:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        out, _ = p.communicate()

        if p.returncode != 0:
            logger.warning(command)
            logger.warning(out)
            logger.error(m18n.n("domain_hostname_failed"))
        else:
            logger.debug(out)


@is_unit_operation(exclude=["dyndns_recovery_password", "password"])
def tools_postinstall(
    operation_logger: OperationLogger,
    domain: str,
    username: str,
    fullname: str,
    password: str,
    dyndns_recovery_password: str | None = None,
    ignore_dyndns: bool = False,
    force_diskspace: bool = False,
    overwrite_root_password: bool = True,
    i_have_read_terms_of_services: bool = False,
) -> None:
    import psutil

    from .app_catalog import _update_apps_catalog
    from .domain import domain_add, domain_main_domain
    from .dyndns import _dyndns_available, dyndns_unsubscribe
    from .permission import _set_system_perms
    from .service import _run_service_command
    from .user import ADMIN_ALIASES, user_create
    from .utils.app_utils import _ask_confirmation
    from .utils.dns import is_yunohost_dyndns_domain
    from .utils.password import (
        assert_password_is_compatible,
        assert_password_is_strong_enough,
    )

    # Do some checks at first
    if os.path.isfile("/etc/yunohost/installed"):
        raise YunohostValidationError("yunohost_already_installed")

    if os.path.isdir("/etc/yunohost/apps") and os.listdir("/etc/yunohost/apps") != []:
        raise YunohostValidationError(
            "It looks like you're trying to re-postinstall a system that was already working previously ... If you recently had some bug or issues with your installation, please first discuss with the team on how to fix the situation instead of savagely re-running the postinstall ...",
            raw_msg=True,
        )

    if Moulinette.interface.type == "cli" and os.isatty(1):
        Moulinette.display(m18n.n("tos_postinstall_acknowledgement"), style="warning")
        if not i_have_read_terms_of_services:
            # i18n: confirm_tos_acknowledgement
            _ask_confirmation("confirm_tos_acknowledgement", kind="soft")

    # Crash early if the username is already a system user, which is
    # a common confusion. We don't want to crash later and end up in an half-configured state.
    all_existing_usernames = {x.pw_name for x in pwd.getpwall()}
    if username in all_existing_usernames:
        raise YunohostValidationError("system_username_exists")

    if username in ADMIN_ALIASES:
        raise YunohostValidationError(
            f"Unfortunately, {username} cannot be used as a username", raw_msg=True
        )

    # Check there's at least 10 GB on the rootfs...
    disk_partitions = sorted(
        psutil.disk_partitions(all=True), key=lambda k: k.mountpoint
    )
    main_disk_partitions = [d for d in disk_partitions if d.mountpoint in ["/", "/var"]]
    main_space = sum(
        psutil.disk_usage(d.mountpoint).total for d in main_disk_partitions
    )
    GB = 1024**3
    if not force_diskspace and main_space < 10 * GB:
        raise YunohostValidationError("postinstall_low_rootfsspace")

    # Check password
    assert_password_is_compatible(password)
    assert_password_is_strong_enough("admin", password)

    # If this is a nohost.me/noho.st, actually check for availability
    dyndns = not ignore_dyndns and is_yunohost_dyndns_domain(domain)
    if dyndns:
        # Check if the domain is available...
        try:
            available = _dyndns_available(domain)
        # If an exception is thrown, most likely we don't have internet
        # connectivity or something. Assume that this domain isn't manageable
        # and inform the user that we could not contact the dyndns host server.
        except Exception:
            raise YunohostValidationError(
                "dyndns_provider_unreachable", provider="dyndns.yunohost.org"
            )
        else:
            if not available:
                if dyndns_recovery_password:
                    # Try to unsubscribe the domain so it can be subscribed again
                    # If successful, it will be resubscribed with the same recovery password
                    dyndns_unsubscribe(
                        domain=domain, recovery_password=dyndns_recovery_password
                    )
                else:
                    raise YunohostValidationError("dyndns_unavailable", domain=domain)

    if os.system("nft -V >/dev/null 2>/dev/null") != 0:
        raise YunohostValidationError(
            "nftables does not seems to be working on your setup. You may be in a container or your kernel does have the proper modules loaded. Sometimes, rebooting the machine may solve the issue.",
            raw_msg=True,
        )

    operation_logger.start()
    logger.info(m18n.n("yunohost_installing"))

    _set_system_perms(
        {
            "ssh": {"allowed": ["admins"]},
            "sftp": {"allowed": []},
            "mail": {"allowed": ["all_users"]},
        }
    )

    # New domain config
    domain_add(
        domain,
        dyndns_recovery_password=dyndns_recovery_password,
        ignore_dyndns=ignore_dyndns,
        skip_tos=True,  # skip_tos is here to prevent re-asking about the ToS when adding a dyndns service, because the ToS are already displayed right before in postinstall
    )
    domain_main_domain(domain)

    # First user
    user_create(username, domain, password, admin=True, fullname=fullname)

    if overwrite_root_password:
        tools_rootpw(password)

    # Try to fetch the apps catalog ...
    # we don't fail miserably if this fails,
    # because that could be for example an offline installation...
    try:
        _update_apps_catalog()
    except Exception as e:
        logger.warning(str(e))

    # Init migrations (skip them, no need to run them on a fresh system)
    _skip_all_migrations()

    os.system("touch /etc/yunohost/installed")

    # Enable and start YunoHost firewall at boot time
    _run_service_command("enable", "nftables")

    tools_regen_conf(names=["ssh"], force=True)

    # Restore original ssh conf, as chosen by the
    # admin during the initial install
    #
    # c.f. the install script and in particular
    # https://github.com/YunoHost/install_script/pull/50
    # The user can now choose during the install to keep
    # the initial, existing sshd configuration
    # instead of YunoHost's recommended conf
    #
    original_sshd_conf = "/etc/ssh/sshd_config.before_yunohost"
    if os.path.exists(original_sshd_conf):
        os.rename(original_sshd_conf, "/etc/ssh/sshd_config")

    tools_regen_conf(force=True)

    logger.success(m18n.n("yunohost_configured"))

    logger.warning(m18n.n("yunohost_postinstall_end_tip"))


def tools_regen_conf(
    names: list[str] = [],
    with_diff: bool = False,
    force: bool = False,
    dry_run: bool = False,
    list_pending: bool = False,
) -> dict[str, dict[str, Any]]:
    from .regenconf import regen_conf

    if (names == [] or "nftables" in names) and tools_migrations_state()[
        "migrations"
    ].get("0032_firewall_config") not in ["skipped", "done"]:
        # Make sure the firewall conf is migrated before running the regenconf,
        # otherwise the nftable regenconf wont work
        try:
            tools_migrations_run(["0032_firewall_config"])
        except Exception as e:
            logger.error(e)

    return regen_conf(names, with_diff, force, dry_run, list_pending)


class AvailableUpdatesInfos(TypedDict):
    system: dict[str, list[dict[str, str]]]
    apps: list["AppInfo"]
    important_yunohost_upgrade: bool
    pending_migrations: list[dict[str, Any]]
    last_apt_update: int
    last_apps_catalog_update: int


def tools_update_norefresh() -> AvailableUpdatesInfos:
    return tools_update(no_refresh=True)


@is_unit_operation(sse_only=True)
def tools_update(
    operation_logger, target=None, no_refresh=False
) -> AvailableUpdatesInfos:
    """
    Update apps & system package cache
    """
    from .app_catalog import _update_apps_catalog

    refresh = not no_refresh

    if not target:
        target = "all"

    if target not in ["system", "apps", "all"]:
        raise YunohostError(
            f"Unknown target {target}, should be 'system', 'apps' or 'all'",
            raw_msg=True,
        )

    if refresh:
        operation_logger.start()

    upgradable_system_packages = []
    if target in ["system", "all"]:
        # Update APT cache
        # LC_ALL=C is here to make sure the results are in english
        command = (
            "LC_ALL=C apt-get update -o Acquire::Retries=3 --allow-releaseinfo-change"
        )

        # Filter boring message about "apt not having a stable CLI interface"
        # Also keep track of whether or not we encountered a warning...
        warnings = []

        def is_legit_warning(m: str) -> bool:
            legit_warning = (
                bool(m.rstrip())
                and "apt does not have a stable CLI interface" not in m.rstrip()
            )
            if legit_warning:
                warnings.append(m)
            return legit_warning

        callbacks = (
            # stdout goes to debug
            lambda l: logger.debug(l.rstrip()),
            # stderr goes to warning except for the boring apt messages
            lambda l: (
                logger.warning(l.rstrip())
                if is_legit_warning(l)
                else logger.debug(l.rstrip())
            ),
        )

        if refresh:
            logger.info(m18n.n("updating_apt_cache"))

            returncode = call_async_output(command, callbacks, shell=True)

            if returncode != 0:
                raise YunohostError(
                    "update_apt_cache_failed",
                    sourceslist="\n".join(_dump_sources_list()),
                )
            elif warnings:
                logger.error(
                    m18n.n(
                        "update_apt_cache_warning",
                        sourceslist="\n".join(_dump_sources_list()),
                    )
                )

            logger.debug(m18n.n("done"))

        upgradable_system_packages = list(_list_upgradable_apt_packages())

    apps = []
    upgradable_apps = []
    if target in ["apps", "all"]:
        if refresh:
            try:
                _update_apps_catalog()
            except YunohostError as e:
                logger.error(str(e))

        apps = _list_apps_with_upgrade_infos()
        upgradable_apps = [
            app
            for app in apps
            if app["upgrade"]["status"] in ["upgradable", "fail_requirements"]
        ]

    if len(upgradable_apps) == 0 and len(upgradable_system_packages) == 0:
        logger.info(m18n.n("already_up_to_date"))

    important_yunohost_upgrade = False
    if upgradable_system_packages and any(
        p["name"] == "yunohost" for p in upgradable_system_packages
    ):
        yunohost = [p for p in upgradable_system_packages if p["name"] == "yunohost"][0]
        current_version = yunohost["current_version"].split(".")[:2]
        new_version = yunohost["new_version"].split(".")[:2]
        important_yunohost_upgrade = current_version != new_version

    upgradable_system_packages_per_categories = _group_packages_per_categories(
        upgradable_system_packages
    )

    # Wrapping this in a try/except just in case for some reason we can't load
    # the migrations, which would result in the update/upgrade process being blocked...
    try:
        pending_migrations = tools_migrations_list(pending=True)["migrations"]
    except Exception as e:
        logger.error(e)
        pending_migrations = []

    try:
        last_apt_update_in_seconds = int(
            time.time() - os.stat("/var/cache/apt/pkgcache.bin").st_mtime
        )
    except Exception as e:
        logger.warning(f"Failed to compute last apt update time ? {e}")
        last_apt_update_in_seconds = 99999 * 3600

    try:
        last_apps_catalog_update_in_seconds = int(
            time.time() - os.stat("/var/cache/yunohost/repo/default.json").st_mtime
        )
    except Exception as e:
        logger.warning(f"Failed to compute last apps catalog update time ? {e}")
        last_apps_catalog_update_in_seconds = 99999 * 3600

    return {
        "system": upgradable_system_packages_per_categories,
        "apps": apps,
        "important_yunohost_upgrade": important_yunohost_upgrade,
        "pending_migrations": pending_migrations,
        "last_apt_update": last_apt_update_in_seconds,
        "last_apps_catalog_update": last_apps_catalog_update_in_seconds,
    }


def _list_apps_with_upgrade_infos(
    with_pre_upgrade_notifications: bool = True,
) -> list["AppInfo"]:
    from .app import _installed_apps, app_info

    apps = []
    for app_id in sorted(_installed_apps()):
        try:
            app_info_dict = app_info(
                app_id,
                with_upgrade_infos=True,
                with_pre_upgrade_notifications=with_pre_upgrade_notifications,
            )
        except Exception as e:
            logger.error(f"Failed to read info for {app_id} : {e}", exc_info=True)
            continue
        if "settings" in app_info_dict:
            del app_info_dict["settings"]

        apps.append(app_info_dict)

    if not with_pre_upgrade_notifications:
        return apps

    return apps


@is_unit_operation()
def tools_upgrade(operation_logger: OperationLogger, target: str | None = None) -> None:
    """
    Update apps & package cache, then display changelog

    Keyword arguments:
       apps -- List of apps to upgrade (or [] to update all apps)
       system -- True to upgrade system
    """

    from .app import app_upgrade

    if dpkg_is_broken():
        raise YunohostValidationError("dpkg_is_broken")

    # Check for obvious conflict with other dpkg/apt commands already running in parallel
    if not dpkg_lock_available():
        raise YunohostValidationError("dpkg_lock_not_available")

    if target not in ["apps", "system"]:
        raise YunohostValidationError(
            "Uhoh ?! tools_upgrade should have 'apps' or 'system' value for argument target",
            raw_msg=True,
        )

    #
    # Apps
    # This is basically just an alias to yunohost app upgrade ...
    #

    if target == "apps":
        # Make sure there's actually something to upgrade

        apps = _list_apps_with_upgrade_infos(with_pre_upgrade_notifications=False)
        upgradable_apps = [
            app["id"]
            for app in apps
            if app["upgrade"]["status"] in ["upgradable", "fail_requirements"]
        ]

        if not upgradable_apps:
            logger.info(m18n.n("apps_already_up_to_date"))
            return

        # Actually start the upgrades

        try:
            app_upgrade(app=upgradable_apps)
        except Exception as e:
            logger.warning(f"unable to upgrade apps: {e}")
            logger.error(m18n.n("app_upgrade_some_app_failed"))

        return

    #
    # System
    #

    if target == "system":
        # Check that there's indeed some packages to upgrade
        upgradables = list(_list_upgradable_apt_packages())
        if not upgradables:
            logger.info(m18n.n("already_up_to_date"))

        logger.info(m18n.n("upgrading_packages"))
        operation_logger.start()

        # Prepare dist-upgrade command
        dist_upgrade = "DEBIAN_FRONTEND=noninteractive"
        if Moulinette.interface.type == "api":
            dist_upgrade += " YUNOHOST_API_RESTART_WILL_BE_HANDLED_BY_YUNOHOST=yes"
        dist_upgrade += " APT_LISTCHANGES_FRONTEND=none"
        dist_upgrade += " apt-get"
        dist_upgrade += (
            " --fix-broken --show-upgraded --assume-yes --quiet -o=Dpkg::Use-Pty=0"
        )
        for conf_flag in ["old", "miss", "def"]:
            dist_upgrade += ' -o Dpkg::Options::="--force-conf{}"'.format(conf_flag)
        dist_upgrade += " dist-upgrade"

        logger.info(m18n.n("tools_upgrade"))

        logger.debug("Running apt command :\n{}".format(dist_upgrade))

        callbacks = (
            lambda l: (
                logger.info("+ " + l.rstrip() + "\r")
                if _apt_log_line_is_relevant(l)
                else logger.debug(l.rstrip() + "\r")
            ),
            lambda l: (
                logger.warning(l.rstrip())
                if _apt_log_line_is_relevant(l)
                else logger.debug(l.rstrip())
            ),
        )
        returncode = call_async_output(dist_upgrade, callbacks, shell=True)

        # If yunohost is being upgraded from the webadmin
        if (
            any(p["name"] == "yunohost" for p in upgradables)
            and Moulinette.interface.type == "api"
        ):
            # Restart the API after 10 sec (at now doesn't support sub-minute times...)
            # We do this so that the API / webadmin still gets the proper HTTP response
            # It's then up to the webadmin to implement a proper UX process to wait 10 sec and then auto-fresh the webadmin
            cmd = 'at -M now >/dev/null 2>&1 <<< "sleep 10; systemctl restart yunohost-api"'
            # For some reason subprocess doesn't like the redirections so we have to use bash -c explicitly...
            subprocess.check_call(["bash", "-c", cmd])

        if returncode != 0:
            upgradables = list(_list_upgradable_apt_packages())
            logger.warning(
                m18n.n(
                    "tools_upgrade_failed",
                    packages_list=", ".join([p["name"] for p in upgradables]),
                )
            )

        logger.success(m18n.n("system_upgraded"))
        operation_logger.success()


@is_unit_operation()
def tools_shutdown(operation_logger: OperationLogger, force: bool = False) -> None:
    shutdown = force
    if not shutdown:
        try:
            # Ask confirmation for server shutdown
            i = Moulinette.prompt(m18n.n("server_shutdown_confirm", answers="y/N"))
        except NotImplementedError:
            pass
        else:
            if i.lower() == "y" or i.lower() == "yes":
                shutdown = True

    if shutdown:
        operation_logger.start()
        logger.warning(m18n.n("server_shutdown"))
        subprocess.check_call(["systemctl", "poweroff"])


@is_unit_operation()
def tools_reboot(operation_logger: OperationLogger, force: bool = False) -> None:
    reboot = force
    if not reboot:
        try:
            # Ask confirmation for restoring
            i = Moulinette.prompt(m18n.n("server_reboot_confirm", answers="y/N"))
        except NotImplementedError:
            pass
        else:
            if i.lower() == "y" or i.lower() == "yes":
                reboot = True
    if reboot:
        operation_logger.start()
        logger.warning(m18n.n("server_reboot"))
        subprocess.check_call(["systemctl", "reboot"])


def tools_shell(command: str | None = None) -> None:
    """
    Launch an (i)python shell in the YunoHost context.

    This is entirely aim for development.
    """

    from .utils.ldap import _get_ldap_interface

    ldap = _get_ldap_interface()

    if command:
        exec(command)
        return

    logger.warning("The \033[1;34mldap\033[0m interface is available in this context")
    try:
        from IPython import embed

        embed()
    except (ImportError, ModuleNotFoundError):
        logger.warning(
            "You don't have IPython installed, consider installing it as it is way better than the standard shell."
        )
        logger.warning("Falling back on the standard shell.")

        import readline  # will allow Up/Down/History in the console

        readline  # to please pyflakes
        import code

        vars = globals().copy()
        vars.update(locals())
        shell = code.InteractiveConsole(vars)
        shell.interact()


def tools_basic_space_cleanup() -> None:
    """
    Basic space cleanup.

    apt autoremove
    apt autoclean
    journalctl vacuum (leaves 50M of logs)
    archived logs removal
    """
    subprocess.run("apt autoremove && apt autoclean", shell=True)
    subprocess.run("journalctl --vacuum-size=50M", shell=True)
    subprocess.run("rm /var/log/*.gz", shell=True)
    subprocess.run("rm /var/log/*/*.gz", shell=True)
    subprocess.run("rm /var/log/*.?", shell=True)
    subprocess.run("rm /var/log/*/*.?", shell=True)
def tools_clean_old_kernels() -> None:
    # Removing kernel except last one
    uname_output = subprocess.run("uname -r", capture_output=True, text=True, shell=True)
    # running_kernel is expected to be something like : 6.1.0-28-amd64
    running_kernel = uname_output.stdout.strip()
    dpkg_output = subprocess.run("dpkg -l | grep '^ii\s*linux-image-[0-9]' | awk '{print $2}'", capture_output=True, text=True, shell=True)
    installed_kernels = dpkg_output.stdout.strip().split("\n")
    # Consider for removal all the installed kernels except the running one
    # + the most recent one (which may be more recent than the running one if system didnt reboot since last kernel upgrade)
    kernels_to_remove = [kernel for kernel in sorted(installed_kernels)[:-1] if running_kernel not in kernel]
    if not kernels_to_remove:
        logger.info("No kernel to remove")
        return
    else:
        from .utils.app_utils import _ask_confirmation
        _ask_confirmation(f"The system is currently running kernel {running_kernel}. This will remove the following kernels : {', '.join(kernels_to_remove)}. Proceed ?")
        cmd = f"apt remove -y --purge {' '.join(kernels_to_remove)}"
        kernel_removal = subprocess.run(cmd, shell=True)
        if kernel_removal.returncode != 0:
            logger.error(f"There was an error during the kernels removal. The return code of the 'apt remove' command is : {kernel_removal.returncode}")


# ############################################ #
#                                              #
#            Migrations management             #
#                                              #
# ############################################ #


def tools_migrations_list(
    pending: bool = False, done: bool = False
) -> dict[str, list[dict[str, Any]]]:
    """
    List existing migrations
    """

    # Check for option conflict
    if pending and done:
        raise YunohostValidationError("migrations_list_conflict_pending_done")

    # Get all migrations
    _migrations = _get_migrations_list()

    # Reduce to dictionaries
    migrations = [
        {
            "id": migration.id,
            "number": migration.number,
            "name": migration.name,
            "mode": migration.mode,
            "state": migration.state,
            "description": migration.description,
            "disclaimer": migration.disclaimer,
        }
        for migration in _migrations
    ]

    # If asked, filter pending or done migrations
    if pending or done:
        if done:
            migrations = [m for m in migrations if m["state"] != "pending"]
        if pending:
            migrations = [m for m in migrations if m["state"] == "pending"]

    return {"migrations": migrations}


def tools_migrations_run(
    targets: list[str] = [],
    skip: bool = False,
    auto: bool = False,
    force_rerun: bool = False,
    accept_disclaimer: bool = False,
) -> None:
    """
    Perform migrations

    targets        A list migrations to run (all pendings by default)
    --skip         Skip specified migrations (to be used only if you know what you are doing) (must explicit which migrations)
    --auto         Automatic mode, won't run manual migrations (to be used only if you know what you are doing)
    --force-rerun  Re-run already-ran migrations (to be used only if you know what you are doing)(must explicit which migrations)
    --accept-disclaimer  Accept disclaimers of migrations (please read them before using this option) (only valid for one migration)
    """

    all_migrations = _get_migrations_list()

    # Small utility that allows up to get a migration given a name, id or number later
    def get_matching_migration(target):
        for m in all_migrations:
            if m.id == target or m.name == target or m.id.split("_")[0] == target:
                return m

        raise YunohostValidationError("migrations_no_such_migration", id=target)

    # Dirty hack to mark the bullseye->bookworm as done ...
    # it may still be marked as 'pending' if for some reason the migration crashed,
    # but the admins ran 'apt full-upgrade' to manually finish the migration
    # ... in which case it won't be magically flagged as 'done' until here
    migrate_to_bookworm = get_matching_migration("migrate_to_bookworm")
    if migrate_to_bookworm.state == "pending":
        migrate_to_bookworm.state = "done"
        _write_migration_state(migrate_to_bookworm.id, "done")

    # auto, skip and force are exclusive options
    if auto + skip + force_rerun > 1:
        raise YunohostValidationError("migrations_exclusive_options")

    # If no target specified
    if not targets:
        # skip, revert or force require explicit targets
        if skip or force_rerun:
            raise YunohostValidationError("migrations_must_provide_explicit_targets")

        # Otherwise, targets are all pending migrations
        migrationtargets = [m for m in all_migrations if m.state == "pending"]

    # If explicit targets are provided, we shall validate them
    else:
        migrationtargets = [get_matching_migration(t) for t in targets]
        done = [t.id for t in migrationtargets if t.state != "pending"]
        pending = [t.id for t in migrationtargets if t.state == "pending"]

        if skip and done:
            raise YunohostValidationError(
                "migrations_not_pending_cant_skip", ids=", ".join(done)
            )
        if force_rerun and pending:
            raise YunohostValidationError(
                "migrations_pending_cant_rerun", ids=", ".join(pending)
            )
        if not (skip or force_rerun) and done:
            raise YunohostValidationError("migrations_already_ran", ids=", ".join(done))

    # So, is there actually something to do ?
    if not migrationtargets:
        logger.info(m18n.n("migrations_no_migrations_to_run"))
        return

    # Actually run selected migrations
    for migration in migrationtargets:
        # If we are migrating in "automatic mode" (i.e. from debian configure
        # during an upgrade of the package) but we are asked for running
        # migrations to be ran manually by the user, stop there and ask the
        # user to run the migration manually.
        if auto and migration.mode == "manual":
            logger.warning(m18n.n("migrations_to_be_ran_manually", id=migration.id))

            # We go to the next migration
            continue

        # Check for migration dependencies
        if not skip:
            dependencies = [
                get_matching_migration(dep) for dep in migration.dependencies
            ]
            pending_dependencies = [
                dep.id for dep in dependencies if dep.state == "pending"
            ]
            if pending_dependencies:
                logger.error(
                    m18n.n(
                        "migrations_dependencies_not_satisfied",
                        id=migration.id,
                        dependencies_id=", ".join(pending_dependencies),
                    )
                )
                continue

        # If some migrations have disclaimers (and we're not trying to skip them)
        if migration.disclaimer and not skip:
            # require the --accept-disclaimer option.
            # Otherwise, go to the next migration
            if not accept_disclaimer:
                logger.warning(
                    m18n.n(
                        "migrations_need_to_accept_disclaimer",
                        id=migration.id,
                        disclaimer=migration.disclaimer,
                    )
                )
                continue
            # --accept-disclaimer will only work for the first migration
            else:
                accept_disclaimer = False

        # Start register change on system
        operation_logger = OperationLogger("tools_migrations_migrate_forward")
        operation_logger.start()

        if skip:
            logger.warning(m18n.n("migrations_skip_migration", id=migration.id))
            migration.state = "skipped"
            _write_migration_state(migration.id, "skipped")
            operation_logger.success()
        else:
            try:
                logger.info(m18n.n("migrations_running_forward", id=migration.id))
                migration.run()
            except Exception as e:
                # migration failed, let's stop here but still update state because
                # we managed to run the previous ones
                msg = m18n.n(
                    "migrations_migration_has_failed", exception=e, id=migration.id
                )
                logger.error(msg, exc_info=True)
                operation_logger.error(msg)
            else:
                logger.success(m18n.n("migrations_success_forward", id=migration.id))
                migration.state = "done"
                _write_migration_state(migration.id, "done")

                operation_logger.success()


def tools_migrations_state() -> dict[str, dict[Any, Any]]:
    """
    Show current migration state
    """
    if not os.path.exists(MIGRATIONS_STATE_PATH):
        return {"migrations": {}}

    return read_yaml(MIGRATIONS_STATE_PATH)  # type: ignore[return-value]


def _write_migration_state(migration_id, state):
    current_states = tools_migrations_state()
    current_states["migrations"][migration_id] = state
    write_to_yaml(MIGRATIONS_STATE_PATH, current_states)


def _get_migrations_list() -> list["Migration"]:
    # states is a datastructure that represents the last run migration
    # it has this form:
    # {
    #     "0001_foo": "skipped",
    #     "0004_baz": "done",
    #     "0002_bar": "skipped",
    #     "0005_zblerg": "done",
    # }
    # (in particular, pending migrations / not already ran are not listed
    states = tools_migrations_state()["migrations"]

    migrations = []
    migrations_folder = os.path.dirname(__file__) + "/migrations/"
    for migration_file in [
        x
        for x in os.listdir(migrations_folder)
        if re.match(r"^\d+_[a-zA-Z0-9_]+\.py$", x)
    ]:
        m = _load_migration(migration_file)
        m.state = states.get(m.id, "pending")
        migrations.append(m)

    return sorted(migrations, key=lambda m: m.id)


def _get_migration_by_name(migration_name):
    """
    Low-level / "private" function to find a migration by its name
    """

    try:
        from . import migrations
    except ImportError:
        raise AssertionError(f"Unable to find migration with name {migration_name}")

    migrations_path = migrations.__path__[0]
    migrations_found = [
        x
        for x in os.listdir(migrations_path)
        if re.match(r"^\d+_%s\.py$" % migration_name, x)
    ]

    assert len(migrations_found) == 1, (
        f"Unable to find migration with name {migration_name}"
    )

    return _load_migration(migrations_found[0])


def _load_migration(migration_file: str) -> "Migration":
    migration_id = migration_file[: -len(".py")]

    logger.debug(m18n.n("migrations_loading_migration", id=migration_id))

    try:
        # this is python builtin method to import a module using a name, we
        # use that to import the migration as a python object so we'll be
        # able to run it in the next loop
        module = import_module("yunohost.migrations.{}".format(migration_id))
        return module.MyMigration(migration_id)
    except Exception as e:
        import traceback

        traceback.print_exc()

        raise YunohostError(
            "migrations_failed_to_load_migration", id=migration_id, error=e
        )


def _skip_all_migrations() -> None:
    """
    Skip all pending migrations.
    This is meant to be used during postinstall to
    initialize the migration system.
    """
    all_migrations = _get_migrations_list()
    new_states: dict[Literal["migrations"], dict[str, str]] = {"migrations": {}}
    for migration in all_migrations:
        new_states["migrations"][migration.id] = "skipped"
    write_to_yaml(MIGRATIONS_STATE_PATH, new_states)  # type: ignore[arg-type]


def _tools_migrations_run_after_system_restore(backup_version: str) -> None:
    all_migrations = _get_migrations_list()

    current_version = version.parse(ynh_packages_version()["yunohost"]["version"])
    backup_version = version.parse(backup_version)

    if backup_version == current_version:
        return

    for migration in all_migrations:
        if (
            hasattr(migration, "introduced_in_version")
            and version.parse(migration.introduced_in_version) > backup_version
            and hasattr(migration, "run_after_system_restore")
        ):
            try:
                logger.info(m18n.n("migrations_running_forward", id=migration.id))
                migration.run_after_system_restore()
            except Exception as e:
                msg = m18n.n(
                    "migrations_migration_has_failed", exception=e, id=migration.id
                )
                logger.error(msg, exc_info=True)
                raise


def _tools_migrations_run_before_app_restore(backup_version, app_id):
    all_migrations = _get_migrations_list()

    current_version = version.parse(ynh_packages_version()["yunohost"]["version"])
    backup_version = version.parse(backup_version)

    if backup_version == current_version:
        return

    for migration in all_migrations:
        if (
            hasattr(migration, "introduced_in_version")
            and version.parse(migration.introduced_in_version) > backup_version
            and hasattr(migration, "run_before_app_restore")
        ):
            try:
                logger.info(m18n.n("migrations_running_forward", id=migration.id))
                migration.run_before_app_restore(app_id)
            except Exception as e:
                msg = m18n.n(
                    "migrations_migration_has_failed", exception=e, id=migration.id
                )
                logger.error(msg, exc_info=1)
                raise


class Migration:
    # Those are to be implemented by daughter classes

    state: Literal["pending", "done", "skipped"] | None = None
    mode: Literal["auto", "manual"] = "auto"
    dependencies: list[
        str
    ] = []  # List of migration ids required before running this migration

    @property
    def disclaimer(self):
        return None

    def run(self):
        raise NotImplementedError()

    # The followings shouldn't be overridden

    def __init__(self, id_) -> None:
        self.id = id_
        self.number = int(self.id.split("_", 1)[0])
        self.name = self.id.split("_", 1)[1]

    @property
    def description(self) -> str:
        return m18n.n(f"migration_description_{self.id}")

    @staticmethod
    def ldap_migration(run) -> Callable:
        def func(self) -> None:
            # Backup LDAP before the migration
            logger.info(m18n.n("migration_ldap_backup_before_migration"))
            try:
                backup_folder = "/home/yunohost.backup/premigration/" + time.strftime(
                    "%Y%m%d-%H%M%S", time.gmtime()
                )
                mkdir(backup_folder, 0o750, parents=True)
                os.system("systemctl stop slapd")
                cp("/etc/ldap", f"{backup_folder}/ldap_config", recursive=True)
                cp("/var/lib/ldap", f"{backup_folder}/ldap_db", recursive=True)
                cp(
                    "/etc/yunohost/apps",
                    f"{backup_folder}/apps_settings",
                    recursive=True,
                )
            except Exception as e:
                raise YunohostError(
                    "migration_ldap_can_not_backup_before_migration", error=str(e)
                )
            finally:
                os.system("systemctl start slapd")

            try:
                run(self, backup_folder)
            except Exception:
                if self.ldap_migration_started:
                    logger.warning(
                        m18n.n("migration_ldap_migration_failed_trying_to_rollback")
                    )
                    os.system("systemctl stop slapd")
                    # To be sure that we don't keep some part of the old config
                    rm("/etc/ldap", force=True, recursive=True)
                    cp(f"{backup_folder}/ldap_config", "/etc/ldap", recursive=True)
                    chown("/etc/ldap/schema/", "openldap", "openldap", recursive=True)
                    chown("/etc/ldap/slapd.d/", "openldap", "openldap", recursive=True)
                    rm("/var/lib/ldap", force=True, recursive=True)
                    cp(f"{backup_folder}/ldap_db", "/var/lib/ldap", recursive=True)
                    rm("/etc/yunohost/apps", force=True, recursive=True)
                    chown("/var/lib/ldap/", "openldap", recursive=True)
                    cp(
                        f"{backup_folder}/apps_settings",
                        "/etc/yunohost/apps",
                        recursive=True,
                    )
                    os.system("systemctl start slapd")
                    rm(backup_folder, force=True, recursive=True)
                    logger.info(m18n.n("migration_ldap_rollback_success"))
                raise
            else:
                rm(backup_folder, force=True, recursive=True)

        return func
