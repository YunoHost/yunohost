# YunoHost core
## Issues
- [Please report issues on YunoHost bugtracker](https://dev.yunohost.org/projects/yunohost/issues) (no registration needed).

## Contribute
- You could develop on this repository using [ynh-dev tool](https://github.com/YunoHost/ynh-dev) with `use-git`  sub-command.
- On this repository we are working [following this workflow](https://yunohost.org/#/build_system_en): `stable <— testing <— branch`.

## Repository content
- Shell [application helpers](https://yunohost.org/#/packaging_apps_helpers_en).
- Services configuration templates.
- Modules for the XMPP server Metronome.
- Debian files for package creation.
- Locales for translations of `yunohost` command.
- YunoHost core Python 2.7 scripts.
- An actionmap used by moulinette.
- Hooks.

## How does it works?
- Python core scripts are accessible through two interfaces thanks to [moulinette framework](https://github.com/YunoHost/moulinette):
 - [CLI](https://en.wikipedia.org/wiki/Command-line_interface) for `yunohost` command.
 - [API](https://en.wikipedia.org/wiki/Application_programming_interface) for [web administration module](https://github.com/YunoHost/yunohost-admin) (other modules could be implemented).
- You could found more details about how YunoHost works on this [documentation (in french)](https://yunohost.org/#/package_list_fr).

## Dependencies
- [Python 2.7](https://www.python.org/download/releases/2.7)
- [Moulinette](https://github.com/YunoHost/moulinette)
- [Bash](https://www.gnu.org/software/bash/bash.html)
- [Debian Jessie](https://www.debian.org/releases/jessie)
