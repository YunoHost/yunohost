[![Build Status](https://travis-ci.org/YunoHost/yunohost.svg?branch=stretch-unstable)](https://travis-ci.org/YunoHost/yunohost)
[![GitHub license](https://img.shields.io/github/license/YunoHost/yunohost)](https://github.com/YunoHost/yunohost/blob/stretch-unstable/LICENSE)

# YunoHost core

This repository is the core of YunoHost code.

- [YunoHost project website](https://yunohost.org)
- [Butracker](https://github.com/YunoHost/issues).

## Contributing

- You can develop on this repository using [ynh-dev](https://github.com/YunoHost/ynh-dev) with `use-git` sub-command.
- On this repository we are [following this workflow](https://yunohost.org/#/build_system_en): `stable <- testing <- unstable <- your_branch`.
- Note: if you modify python scripts, you will have to modifiy the actions map.
- You can help with translation on [our translation platform](https://translate.yunohost.org/engage/yunohost/?utm_source=widget)

<img src="https://translate.yunohost.org/widgets/yunohost/-/multi-auto.svg" alt="Translation status" />


## Repository content

- [YunoHost core Python 2.7 scripts](./src/yunohost).
- [An actionsmap](./data/actionsmap/yunohost.yml) used by moulinette.
- [Services configuration templates](./data/templates).
- [Hooks](./data/hooks).
- [Locales](./locales) for translations of `yunohost` command.
- [Shell helpers](./helpers.d) for [application packaging](https://yunohost.org/#/packaging_apps_helpers_en).
- [Modules for the XMPP server Metronome](./lib/metronome/modules).
- [Debian files](./debian) for package creation.

## How does it work?

- Python core scripts are accessible through two interfaces thanks to the [moulinette framework](https://github.com/YunoHost/moulinette):
 - [CLI](https://en.wikipedia.org/wiki/Command-line_interface) for `yunohost` command.
 - [API](https://en.wikipedia.org/wiki/Application_programming_interface) for [web administration module](https://github.com/YunoHost/yunohost-admin) (other modules could be implemented).
- You can find more details about how YunoHost works on this [documentation (in french)](https://yunohost.org/#/package_list_fr).

## Dependencies

- [Python 2.7](https://www.python.org/download/releases/2.7)
- [Moulinette](https://github.com/YunoHost/moulinette)
- [Bash](https://www.gnu.org/software/bash/bash.html)
- [Debian Stretch](https://www.debian.org/releases/stretch)

## License

As [other components of YunoHost core code](https://yunohost.org/#/faq_en), this repository is under GNU AGPL v.3 license.
