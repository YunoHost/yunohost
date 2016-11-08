# YunoHost core
## Issues
- [Please report issues on YunoHost bugtracker](https://dev.yunohost.org/projects/yunohost/issues) (no registration needed).

## Contribute
- You can develop on this repository using [ynh-dev tool](https://github.com/YunoHost/ynh-dev) with `use-git`  sub-command.
- On this repository we are [following this workflow](https://yunohost.org/#/build_system_en): `stable <— testing <— branch`.
- Note: if you modify python scripts, you will have to modifiy the action map.

## Repository content
- [YunoHost core Python 2.7 scripts](https://github.com/YunoHost/yunohost/tree/stable/src/yunohost).
- [An actionmap](https://github.com/YunoHost/yunohost/blob/stable/data/actionsmap/yunohost.yml) used by moulinette.
- [Services configuration templates](https://github.com/YunoHost/yunohost/tree/stable/data/templates).
- [Hooks](https://github.com/YunoHost/yunohost/tree/stable/data/hooks).
- [Locales](https://github.com/YunoHost/yunohost/tree/stable/locales) for translations of `yunohost` command.
- [Shell helpers](https://github.com/YunoHost/yunohost/tree/stable/data/helpers.d) for [application packaging](https://yunohost.org/#/packaging_apps_helpers_en).
- [Modules for the XMPP server Metronome](https://github.com/YunoHost/yunohost/tree/stable/lib/metronome/modules).
- [Debian files](https://github.com/YunoHost/yunohost/tree/stable/debian) for package creation.

## How does it works?
- Python core scripts are accessible through two interfaces thanks to the [moulinette framework](https://github.com/YunoHost/moulinette):
 - [CLI](https://en.wikipedia.org/wiki/Command-line_interface) for `yunohost` command.
 - [API](https://en.wikipedia.org/wiki/Application_programming_interface) for [web administration module](https://github.com/YunoHost/yunohost-admin) (other modules could be implemented).
- You can find more details about how YunoHost works on this [documentation (in french)](https://yunohost.org/#/package_list_fr).

## Dependencies
- [Python 2.7](https://www.python.org/download/releases/2.7)
- [Moulinette](https://github.com/YunoHost/moulinette)
- [Bash](https://www.gnu.org/software/bash/bash.html)
- [Debian Jessie](https://www.debian.org/releases/jessie)
