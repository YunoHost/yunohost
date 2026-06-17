#!/usr/bin/env python3
#
# Copyright (c) 2026 YunoHost Contributors
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
from typing import Literal
from logging import getLogger
from moulinette import m18n

logger = getLogger("yunohost.utils.email")

# This secret is provisionned during the 01-yunohost regenconf, along with the cookie secrets etc
ROOT_EMAIL_PASSWORD_FILE = "/etc/yunohost/.email_auth_secret"

def _send_email(_from: str, to: str, subject: str, body: str, no_reply: str | None = None) -> None:

    from smtplib import SMTP
    from email.message import EmailMessage
    from .file_utils import read_file
    from .dns import dig

    recipient_is_external = "@" in to
    if recipient_is_external:
        recipient_domain = to.split("@")[-1]
        ok, _ = dig(recipient_domain, "MX")
        if ok != "ok":
            logger.warning(m18n.n("skipping_email_no_mx_for_domain", recipient_domain=recipient_domain))
            return

        from_domain = _from.split()[0].split("@")[1]
        ok2, message = _domain_is_able_to_send_email(from_domain)
        if ok2 == "warning":
            logger.warning(message)
        elif ok2 is False:
            logger.error(message)
            logger.error(m18n.n("skipping_email"))
            return

    msg = EmailMessage()
    msg['From'] = _from
    if no_reply:
        msg['Reply-To'] = no_reply
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)

    with SMTP("localhost") as smtp:
        # If the recipient is external, we need to auth on the mail stack for
        # the message to be DKIM-signed However, it also means that the from
        # address we may use need to be enabled for root, cf the postfix sender
        # map in regen_mail_senders_infos_for_dovecot_and_postfix
        if recipient_is_external:
            password = read_file(ROOT_EMAIL_PASSWORD_FILE).strip()
            smtp.starttls()  # For some reason, this is necessary to login?
            smtp.login("root", password)
        smtp.send_message(msg)


def regen_mail_senders_infos_for_dovecot_and_postfix(
    only: Literal["dovecot", "postfix"] | None = None,
) -> None:
    dovecot = True if only in [None, "dovecot"] else False
    postfix = True if only in [None, "postfix"] else False

    from .password import _hash_user_password
    from .file_utils import chmod, chown, read_file, write_to_file
    from ..apps import _installed_apps, _get_app_settings

    postfix_map = []
    dovecot_passwd = []

    # Also need a root account that can authenticate on the mail stack
    # to be able to send external emails which are DKIM-signed
    # (ofc it would be much easier if we could use unix sock auth or something but hmpf)
    if dovecot:
        password = read_file(ROOT_EMAIL_PASSWORD_FILE).strip()
        hashed_password = _hash_user_password(password)
        dovecot_passwd.append(
            f"root:{hashed_password}::::::allow_nets=::1,127.0.0.1/24"
        )
    if postfix:

        # This function is called by the regen conf script
        # and we can get the info from there ... instead of using domain_list(...) with features= arg,
        # which then calls a bunch of config panel shenanigans and we don't have enough context loaded in there (it crashes because of translation whatev)...
        mail_out_domains = os.environ["YNH_DOMAINS_WITH_MAIL_OUT"].split(" ")
        main_domains = os.environ["YNH_MAIN_DOMAINS"].split(" ")
        for mail_domain in mail_out_domains:
            if mail_domain not in main_domains:
                continue
            for mail_user in ["root", "admin", "admins", "no-reply", "registrations"]:
                postfix_map.append(f"{mail_user}@{mail_domain} root")

    # Now for the app credentials
    for app in _installed_apps():
        settings = _get_app_settings(app)

        if "domain" not in settings or "mail_pwd" not in settings:
            continue

        mail_user = settings.get("mail_user", app)
        mail_domain = settings.get("mail_domain", settings["domain"])

        if dovecot:
            hashed_password = _hash_user_password(settings["mail_pwd"])
            dovecot_passwd.append(
                f"{app}:{hashed_password}::::::allow_nets=::1,127.0.0.1/24,local,mail={mail_user}@{mail_domain}"
            )
        if postfix:
            postfix_map.append(f"{mail_user}@{mail_domain} {app}")

    if dovecot:
        app_senders_passwd = "/etc/dovecot/app-senders-passwd"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(dovecot_passwd)
        write_to_file(app_senders_passwd, content)
        chmod(app_senders_passwd, 0o440)
        chown(app_senders_passwd, "root", "dovecot")

    if postfix:
        app_senders_map = "/etc/postfix/app_senders_login_maps"
        content = "# This file is regenerated automatically.\n# Please DO NOT edit manually ... changes will be overwritten!"
        content += "\n" + "\n".join(postfix_map)
        write_to_file(app_senders_map, content)
        chmod(app_senders_map, 0o440)
        chown(app_senders_map, "postfix", "root")
        ret = os.system(f"postmap {app_senders_map} 2>/dev/null")
        if ret != 0:
            logger.error(f"Uhoh, failed to run 'postmap {app_senders_map}' ?!")
        chmod(app_senders_map + ".db", 0o640)
        chown(app_senders_map + ".db", "postfix", "root")


def _domain_is_able_to_send_email(domain) -> tuple[Literal[True], None] | tuple[Literal[False, "warning"], str]:

    # FIXME: i18n?

    from ..settings import settings_get
    from ..diagnosis import Diagnoser
    from ..domain import _get_raw_domain_settings

    # Check outgoing email is enabled in this domain setting
    # NB : check note in _get_raw_domain_settings, hard-coded stuff for mail_in/mail_out
    # to avoid relying on domain_config_get
    if not bool(_get_raw_domain_settings(domain).get("mail_out")):
        return False, f"Outgoing email is not enabled for domain {domain}"

    failed_service = [service for service in ["postfix@-", "dovecot", "opendkim"] if os.system(f"systemctl is-active --quiet {service}") != 0]
    if failed_service:
        return False, f"Critical services of the mail stack are down ({', '.join(failed_service)}), therefore sending email will not work"

    # Check the A/AAAA records, necessary to send email
    basic_dnsrecords = (
        Diagnoser.get_cached_report(
            "dnsrecords",
            item={"domain": domain, "category": "basic"},
            warn_if_no_cache=False,
        )
        or {}
    )
    if not basic_dnsrecords:
        return False, f"Basic A/AAAA DNS records are not configured at all for domain {domain} (or no diagnosis result yet)"
    elif basic_dnsrecords.get("status") != "SUCCESS":
        return False, f"The A/AAAA DNS records are not properly configured for domain {domain}, sending email will not work."

    # Mail-specific DNS records
    #
    # Let's focus on checking the DKIM record, because strictly speaking you
    # don't really need an MX record to send email etc?  or at least, it's
    # okay-ish if the SPF/DMARC are not configured according to the
    # recommendation, sometimes people tweak it for legit reasons
    mail_dnsrecords = (
        Diagnoser.get_cached_report(
            "dnsrecords",
            item={"domain": domain, "category": "mail"},
            warn_if_no_cache=False,
        )
        or {}
    )
    if not mail_dnsrecords:
        return False, f"Email-related DNS records are not configured at all for domain {domain} (or no diagnosis result yet)"
    dkim_record_ok = all(status == "OK" for type_and_name, status in mail_dnsrecords.get("data", {}).items() if "_domainkey" in type_and_name)
    if not dkim_record_ok:
        return False, f"The DKIM DNS records for domain {domain} is not properly configured, sending email will probably not work."

    # Check other mail aspects
    # such as port 25, rDNS etc ...
    # though these are probably not relevant when using a mail relay ?
    uses_smtp_relay = bool(settings_get("email.smtp.smtp_relay_host"))
    if not uses_smtp_relay:
        checks = [
            "outgoing_port_25",
            "ehlo",
            "fcrdns",
            "blocklist",
        ]
        failed_checks = []
        for check in checks:
            check_result = Diagnoser.get_cached_report(
                "mail", item={"test": "mail_" + check}, warn_if_no_cache=False
            ) or {}
            if not check_result:
                return False, "Some diagnosis results for email-related checks are not yet available."
            elif check_result.get("status") != "SUCCESS":
                failed_checks.append(check)

        if "outgoing_port_25" in failed_checks:
            return False, "As reported by the diagnosis, outgoing port 25 seems to be blocked, and sending email not work."
        elif failed_checks:
            return "warning", "Issues related to emails found in the diagnosis, such as reverse DNS or the server being blocklisted, indicate that sending email may not work"

    return True, None
