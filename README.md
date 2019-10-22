<p align="center">
    <img alt="YunoHost" src="https://raw.githubusercontent.com/YunoHost/doc/master/images/logo_roundcorner.png" width="100px" />
</p>

<h1 align="center">YunoHost</h1>

<div align="center">

[![Build status](https://travis-ci.org/YunoHost/yunohost.svg?branch=stretch-unstable)](https://travis-ci.org/YunoHost/yunohost)
[![GitHub license](https://img.shields.io/github/license/YunoHost/yunohost)](https://github.com/YunoHost/yunohost/blob/stretch-unstable/LICENSE)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/28084)](https://mastodon.social/@yunohost)

</div>

YunoHost is an operating system aiming to simplify as much as possible the administration of a server.

This repository corresponds to the core code of YunoHost, mainly written in Python and Bash.

- [Project features](https://yunohost.org/#/whatsyunohost)
- [Project website](https://yunohost.org)
- [Install documentation](https://yunohost.org/install)
- [Issue tracker](https://github.com/YunoHost/issues)

# Screenshots

Webadmin ([Yunohost-Admin](https://github.com/YunoHost/yunohost-admin)) | Single sign-on user portal ([SSOwat](https://github.com/YunoHost/ssowat))
--- |  ---
![](https://raw.githubusercontent.com/YunoHost/doc/master/images/webadmin.png) | ![](https://raw.githubusercontent.com/YunoHost/doc/master/images/user_panel.png)


## Contributing

- You can learn how to get started with developing on YunoHost by reading [this piece of documentation](https://yunohost.org/dev).
- Come chat with us on the [dev chatroom](https://yunohost.org/#/chat_rooms) !
- You can help translate YunoHost on our [translation platform](https://translate.yunohost.org/engage/yunohost/?utm_source=widget)

<img src="https://translate.yunohost.org/widgets/yunohost/-/multi-auto.svg" alt="Translation status" />


## Repository content

- [YunoHost core Python 2.7 scripts](./src/yunohost).
- [An actionsmap](./data/actionsmap/yunohost.yml) describing the CLI and API
- [Services configuration templates](./data/templates).
- [Hooks](./data/hooks).
- [Locales](./locales) for translations of `yunohost` command.
- [Shell helpers](./helpers.d) for [application packaging](https://yunohost.org/#/packaging_apps_helpers_en).
- [Modules for the XMPP server Metronome](./lib/metronome/modules).
- [Debian files](./debian) for package creation.

## How does it work?

- Python core scripts are accessible through two interfaces thanks to the [moulinette framework](https://github.com/YunoHost/moulinette):
  - the [CLI](https://en.wikipedia.org/wiki/Command-line_interface) corresponding to the `yunohost` command.
  - the [API](https://en.wikipedia.org/wiki/Application_programming_interface) used by the [web administration interface](https://github.com/YunoHost/yunohost-admin) (other interfaces could be implemented).
- You can find more details about how YunoHost works on this [documentation (in French)](https://yunohost.org/#/package_list_fr).

## License

As [other components of YunoHost](https://yunohost.org/#/faq_en), this repository is licensed GNU AGPL v3.
