import os
import subprocess
import time
import re
import copy
from pathlib import Path
from tempfile import TemporaryDirectory
from logging import getLogger

from .process import call_async_output
from .system import _apt_log_line_is_relevant
from .error import YunohostError, YunohostPackagingError

logger = getLogger("apt")

DEFAULT_PHP_VERSION = "8.2"
PSQL_VERSION = "15"


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Force output in english
    env["LC_ALL"] = "C"
    logger.debug(f"Running: {' '.join(cmd)}")
    p = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **kwargs)
    return p


# Check either a package is installed or not
def _package_is_installed(package: str) -> bool:
    p = _run(["dpkg-query", "--show", "--showformat='${db:Status-Status}'", package])
    return p.stdout.decode().strip("'").startswith("installed")


def _wait_for_dpkg_to_be_free() -> None:

    # Wait up to 15min-ish for dpkg to be free
    for i in range(1, 14):
        # Check if /var/lib/dpkg/lock is used by another process
        if os.system("lsof /var/lib/dpkg/lock > /dev/null") == 0:
            if i > 5:
                logger.info("apt is being used by another process... waiting ...")
            else:
                logger.debug("apt is being used by another process...")
            # Sleep an "exponential" amount of time at each round
            time.sleep(i * i)
            continue

        # Check if dpkg hasn't been interrupted and is fully available.
        # See this for more information:
        # https://sources.debian.org/src/apt/1.4.9/apt-pkg/deb/debsystem.cc/#L141-L174
        for dpkg_file in os.listdir("/var/lib/dpkg/updates/"):
            # Check if the name of this file contains only numbers. If so, that a remaining of dpkg.
            if dpkg_file.isdigit():
                raise Exception("dpkg was interrupted, you must manually run 'sudo dpkg --configure -a' to correct the problem.")
        return

    logger.warning("apt still used, but timeout reached !")


def _apt_update(args: list[str] = []) -> None:

    # Optimization when just calling apt update : check if the cache was
    # already refreshed in the last 30 min, which should be enough and prevent
    # unecessary traffic and annoying wait time during app dependency installs etc
    if not args:
        time.sleep(1)
        apt_cache = Path("/var/cache/apt/pkgcache.bin")
        if apt_cache.exists() \
            and _run(["find", str(apt_cache), "-mmin", "-30"]).stdout.decode().strip() \
            and not _run(["find", "/etc/apt", "-newer", str(apt_cache)]).stdout.decode().strip():
            logger.debug("apt cache was already updated in the last 30 minutes, skipping 'apt update'")
            return

    _apt(["update"] + args)


# APT wrapper for non-interactive operation
def _apt(args: list[str]) -> tuple[bool, list[str]]:

    logs = []

    def strip_boring_dpkg_reading_database(line: str) -> str:
        return re.sub(
            r"(\(Reading database ... \d*%?|files and directories currently installed.\))",
            "",
            line,
        )

    def stdout(line) -> None:
        cleanedline = strip_boring_dpkg_reading_database(line).rstrip()
        if cleanedline.strip():
            logs.append(line)
            logger.debug(cleanedline + "\r")

    def stderr(line) -> None:
        line = line.rstrip()
        if "has no installation candidate" in line:
            logger.error(line + "\r")
        elif "E: Packages need to be removed" not in line and _apt_log_line_is_relevant(line):
            logger.warning(line + "\r")
        else:
            stdout(line)

    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["DEBIAN_FRONTEND"] = "noninteractive"

    _wait_for_dpkg_to_be_free()
    cmd = ["apt-get", "--assume-yes", "--quiet", "-o=Acquire::Retries=3", "-o=Dpkg::Use-Pty=0"] + args
    logger.debug(f"Running: {' '.join(cmd)}")
    ret = call_async_output(cmd, (stdout, stderr), env=env)
    return ret == 0, logs


def _apt_install(args: list[str]) -> tuple[bool, list[str]]:
    return _apt([
        "--no-remove",
        "--option", "Dpkg::Options::=--force-confdef",
        "--option", "Dpkg::Options::=--force-confold",
        "install"
    ] + args)


def apt_install_dependencies(app: str, version: str, packages: list[str], append=False) -> None:

    from ..app import app_setting

    app_ynh_deps = f"{app}-ynh-deps".replace("_", "-")

    # Handle the "append" option
    if append and _package_is_installed(app_ynh_deps):
        p = _run(["dpkg-query", "--show", "--showformat='${Depends}'", app_ynh_deps])
        current_packages = p.stdout.decode().strip().split(", ")
        packages = current_packages + packages

    # Auto-define the "php_version" setting according to php dependencies, if there's any
    # (also auto-add phpX.Y, phpX.Y-fpm and phpX.Y-common if they ain't explicitly provided)
    packages = copy.copy(packages)
    php_packages = [p for p in packages if "-" in p and p.startswith("php") and not p.startswith("php-")]
    php_packages_version = set(p.split("-")[0].replace("php", "") for p in php_packages)
    if len(php_packages_version) > 1:
        raise YunohostPackagingError(f"The list of dependencies refers to more than one php version ?! PHP packages in the dependency list: {', '.join(php_packages)}")
    elif len(php_packages_version) == 1:
        php_version = php_packages_version.pop()
        for package in [f"php{php_version}", f"php{php_version}-fpm", f"php{php_version}-common"]:
            if package not in packages:
                packages.append(package)
        app_setting(app, "php_version", php_version)
    else:
        app_setting(app, "php_version", delete=True)

    psql_is_installed_initially = _package_is_installed(f"postgresql-{PSQL_VERSION}")
    _apt_update()

    with TemporaryDirectory(prefix="ynh_apt_", dir="/tmp/") as d:
        # dpkg-deb insists for folder perm to be 755
        DEBIAN_dir = Path(d) / app_ynh_deps / "DEBIAN"
        DEBIAN_dir.mkdir(mode=0o755, parents=True)
        with (DEBIAN_dir / "control").open("w") as f:
            f.write(f"""
Section: misc
Priority: optional
Package: {app_ynh_deps}
Version: {version}
Depends: {', '.join(packages)}
Architecture: all
Maintainer: root@localhost
Description: Fake package for {app} (YunoHost app) dependencies
 This meta-package is only responsible of installing its dependencies.
""")
        logger.debug((DEBIAN_dir / "control").open().read())

        _wait_for_dpkg_to_be_free()

        # Install the fake package without its dependencies with dpkg --force-depends
        p = _run(["dpkg-deb", "--build", f"{d}/{app_ynh_deps}", f"{d}/{app_ynh_deps}.deb"])
        if p.returncode != 0:
            raise Exception(f"Failed to build virtual dependency {app_ynh_deps}: {p.stdout.decode()}")

        # Don't crash in case of error, because is nicely covered by the following line
        p = _run(["dpkg", "--force-depends", "--install", f"{d}/{app_ynh_deps}.deb"])

        # Then install the missing dependencies with apt install --fix-broken
        success, logs = _apt_install(["--fix-broken"])
        if not success:
            # cat "$TMPDIR/dpkg_log"

            # Parse the list of problematic dependencies from dpkg's log ...
            # (relevant lines look like: "foo-ynh-deps depends on bar; however:")
            problematic_packages = re.findall(r'(?<=-ynh-deps depends on ).*(?=; however)', p.stdout.decode())
            # Fake an install of those dependencies to see the errors
            if problematic_packages:
                success, logs = _apt_install(problematic_packages + ["--dry-run"])
                # The sed command here is, Print only from 'Reading state info' to the end.
                # | sed --quiet '/Reading state info/,$p' | grep -v "fix-broken\|Reading state info" >&2
            raise YunohostError("Unable to install apt dependencies", raw_msg=True)

    # check if the package is actually installed
    if not _package_is_installed(app_ynh_deps):
        raise YunohostError("Unable to install apt dependencies", raw_msg=True)

    # Make sure we don't mess with the default 'php' bin because idk
    php_bin_default = Path(f"/usr/bin/php{DEFAULT_PHP_VERSION}")
    php_bin = Path("/usr/bin/php")
    if php_bin.exists() and php_bin_default.exists() and str(php_bin.resolve()) != str(php_bin):
        os.system(f"update-alternatives --set php {php_bin_default} >/dev/null 2>/dev/null")

    # Trigger postgresql regenconf if we may have just installed postgresql
    psql_is_installed_after = _package_is_installed(f"postgresql-{PSQL_VERSION}")
    if not psql_is_installed_initially and psql_is_installed_after:
        from ..regen_conf import regen_conf
        regen_conf(["postgresql"])


# Remove virtual package for the app
def apt_remove_dependencies(app: str) -> None:
    app_ynh_deps = f"{app}-ynh-deps".replace("_", "-")

    # Edge case where the app dep may be on hold,
    # cf https://forum.yunohost.org/t/migration-error-cause-of-ffsync/20675/4
    if os.system(f"apt-mark showhold | grep -q -w '{app_ynh_deps}'") == 0:
        os.system("apt-mark unhold app_ynh_deps")

    # Remove the fake package and its dependencies if they not still used.
    # (except if dpkg doesn't know anything about the package,
    # which should be symptomatic of a failed install, and we don't want bash to report an error)
    if _package_is_installed(app_ynh_deps):
        returncode, logs = _apt(["autoremove", "--purge", app_ynh_deps])
        logs_joined = '\n'.join(logs)
        assert returncode == 0, f"Uhoh, removing virtual apt package {app_ynh_deps} failed !? Logs:\n{logs_joined}"


# Install packages from an extra repository properly.
def apt_install_dependencies_from_extra_repository(app: str, version: str, repo: str, packages: list[str], key: str) -> None:

    import requests  # lazy loading this module for performance reasons

    if repo.startswith("deb "):
        repo = repo.replace("deb ", "")

    uri, suite, components = repo.split(" ", 2)
    if "://" not in uri:
        raise YunohostPackagingError(f"Repo url for apt extra dependencies '{uri}' doesn't contain any '://' separator ?")
    repo_domain = uri.split("://")[1].split("/")[0]

    sources_list_d = Path("/etc/apt/sources.list.d")
    preferences_d = Path("/etc/apt/preferences.d")
    trusted_gpg_d = Path("/etc/apt/trusted.gpg.d")
    for dir_ in [sources_list_d, preferences_d, trusted_gpg_d]:
        if not dir_.exists():
            dir_.mkdir(mode=0o755, parents=True)

    sources_list_app = sources_list_d / f"{app}.list"
    apt_preferences_app = preferences_d / app
    key_app = trusted_gpg_d / f"{app}.gpg"

    try:
        # Add the new repo in sources.list.d
        sources_list_app.write_text(f"deb {uri} {suite} {components}")

        # Pin the new repo with the default priority, so it won't be used to upgrade already-installed packages
        apt_preferences_app.write_text('\n'.join([
            "Package: *",
            f"Pin: origin {repo_domain}",
            "Pin-Priority: 995"
        ]))

        r = requests.get(key, timeout=300)
        assert r.status_code == 200
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in r.text
        key_app.write_bytes(_run(["gpg", "--dearmor"], input=r.text).stdout)

        # Update the list of package with the new repo NB: we use -o
        # Dir::Etc::sourcelist to only refresh this repo, because
        # ynh_apt_install_dependencies will also call an ynh_apt update on its own
        # and it's good to limit unecessary requests ...  Here we mainly want to
        # validate that the url+key is correct before going further
        _apt_update(["-o", f'Dir::Etc::sourcelist="{sources_list_app}'])

        # Force the cache to be reupdated on the next "apt update" (in
        # ynh_apt_install_dependencies) because the previous command with
        # ::sourcelist option makes apt forget about every other package for other,
        # so we want to force the cache to be reupdated entirely
        sources_list_app.touch()

        # Install requested dependencies from this extra repository.
        apt_install_dependencies(app, version, packages, append=True)

        # Force to upgrade to the last version...
        # Without doing apt install, an already installed dep is not upgraded
        auto_installed_packages = _run(["apt-mark", "showauto"] + packages).stdout.decode().strip().split("\n")
        _apt_install(packages + ["--mark-auto"])
        # Reflag the packages as 'auto' (because apt_install) will have them flagged as manually installed
        if auto_installed_packages:
            _run(["apt-mark", "auto"] + auto_installed_packages)

    finally:
        for file in [sources_list_app, apt_preferences_app, key_app]:
            file.unlink(missing_ok=True)
        _apt_update()
