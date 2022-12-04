#
# Copyright (c) 2022 YunoHost Contributors
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
import sys
import shutil
import subprocess
import glob

from datetime import datetime

from moulinette import m18n
from moulinette.utils.log import getActionLogger
from moulinette.utils.filesystem import read_file, chown, chmod
from moulinette.utils.process import check_output

from yunohost.vendor.acme_tiny.acme_tiny import get_crt as sign_certificate
from yunohost.utils.error import YunohostError, YunohostValidationError
from yunohost.utils.network import get_public_ip

from yunohost.diagnosis import Diagnoser
from yunohost.service import _run_service_command
from yunohost.regenconf import regen_conf
from yunohost.log import OperationLogger

logger = getActionLogger("yunohost.certmanager")

CERT_FOLDER = "/etc/yunohost/certs/"
TMP_FOLDER = "/tmp/acme-challenge-private/"
WEBROOT_FOLDER = "/tmp/acme-challenge-public/"

SELF_CA_FILE = "/etc/ssl/certs/ca-yunohost_crt.pem"
ACCOUNT_KEY_FILE = "/etc/yunohost/letsencrypt_account.pem"

SSL_DIR = "/usr/share/yunohost/ssl"

KEY_SIZE = 3072

VALIDITY_LIMIT = 15  # days

# For prod
PRODUCTION_CERTIFICATION_AUTHORITY = "https://acme-v02.api.letsencrypt.org"

#
# Front-end stuff                                                           #
#


def certificate_status(domains, full=False):
    """
    Print the status of certificate for given domains (all by default)

    Keyword argument:
        domains     -- Domains to be checked
        full        -- Display more info about the certificates
    """

    from yunohost.domain import domain_list, _assert_domain_exists

    # If no domains given, consider all yunohost domains
    if domains == []:
        domains = domain_list()["domains"]
    # Else, validate that yunohost knows the domains given
    else:
        for domain in domains:
            _assert_domain_exists(domain)

    certificates = {}

    for domain in domains:
        status = _get_status(domain)

        if not full:
            del status["subject"]
            del status["CA_name"]

        if full:
            try:
                _check_domain_is_ready_for_ACME(domain)
                status["ACME_eligible"] = True
            except Exception as e:
                if e.key == "certmanager_domain_not_diagnosed_yet":
                    status["ACME_eligible"] = None  # = unknown status
                else:
                    status["ACME_eligible"] = False

        del status["domain"]
        certificates[domain] = status

    return {"certificates": certificates}


def certificate_install(domain_list, force=False, no_checks=False, self_signed=False):
    """
    Install a Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domain_list  -- Domains on which to install certificates
        force        -- Install even if current certificate is not self-signed
        no-check     -- Disable some checks about the reachability of web server
                       before attempting the install
        self-signed  -- Instal self-signed certificates instead of Let's Encrypt
    """

    if self_signed:
        _certificate_install_selfsigned(domain_list, force)
    else:
        _certificate_install_letsencrypt(domain_list, force, no_checks)


def _certificate_install_selfsigned(domain_list, force=False):

    failed_cert_install = []
    for domain in domain_list:

        operation_logger = OperationLogger(
            "selfsigned_cert_install", [("domain", domain)], args={"force": force}
        )

        # Paths of files and folder we'll need
        date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")
        new_cert_folder = f"{CERT_FOLDER}/{domain}-history/{date_tag}-selfsigned"

        conf_template = os.path.join(SSL_DIR, "openssl.cnf")

        csr_file = os.path.join(SSL_DIR, "certs", "yunohost_csr.pem")
        conf_file = os.path.join(new_cert_folder, "openssl.cnf")
        key_file = os.path.join(new_cert_folder, "key.pem")
        crt_file = os.path.join(new_cert_folder, "crt.pem")
        ca_file = os.path.join(new_cert_folder, "ca.pem")

        # Check we ain't trying to overwrite a good cert !
        current_cert_file = os.path.join(CERT_FOLDER, domain, "crt.pem")
        if not force and os.path.isfile(current_cert_file):
            status = _get_status(domain)

            if status["style"] == "success":
                raise YunohostValidationError(
                    "certmanager_attempt_to_replace_valid_cert", domain=domain
                )

        operation_logger.start()

        # Create output folder for new certificate stuff
        os.makedirs(new_cert_folder)

        # Create our conf file, based on template, replacing the occurences of
        # "yunohost.org" with the given domain
        with open(conf_file, "w") as f, open(conf_template, "r") as template:
            for line in template:
                f.write(line.replace("yunohost.org", domain))

        # Use OpenSSL command line to create a certificate signing request,
        # and self-sign the cert
        commands = [
            f"openssl req -new -config {conf_file} -out {csr_file} -keyout {key_file} -nodes -batch",
            f"openssl ca -config {conf_file} -days 3650 -in {csr_file} -out {crt_file} -batch",
        ]

        for command in commands:
            p = subprocess.Popen(
                command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )

            out, _ = p.communicate()

            out = out.decode("utf-8")

            if p.returncode != 0:
                logger.warning(out)
                raise YunohostError("domain_cert_gen_failed")
            else:
                logger.debug(out)

        # Link the CA cert (not sure it's actually needed in practice though,
        # since we append it at the end of crt.pem. For instance for Let's
        # Encrypt certs, we only need the crt.pem and key.pem)
        os.symlink(SELF_CA_FILE, ca_file)

        # Append ca.pem at the end of crt.pem
        with open(ca_file, "r") as ca_pem, open(crt_file, "a") as crt_pem:
            crt_pem.write("\n")
            crt_pem.write(ca_pem.read())

        # Set appropriate permissions
        _set_permissions(new_cert_folder, "root", "root", 0o755)
        _set_permissions(key_file, "root", "ssl-cert", 0o640)
        _set_permissions(crt_file, "root", "ssl-cert", 0o640)
        _set_permissions(conf_file, "root", "root", 0o600)

        # Actually enable the certificate we created
        _enable_certificate(domain, new_cert_folder)

        # Check new status indicate a recently created self-signed certificate
        status = _get_status(domain)

        if status and status["CA_type"] == "selfsigned" and status["validity"] > 3648:
            logger.success(
                m18n.n("certmanager_cert_install_success_selfsigned", domain=domain)
            )
            operation_logger.success()
        else:
            msg = f"Installation of self-signed certificate installation for {domain} failed !"
            failed_cert_install.append(domain)
            logger.error(msg)
            logger.error(status)
            operation_logger.error(msg)

    if failed_cert_install:
        raise YunohostError(
            "certmanager_cert_install_failed_selfsigned",
            domains=",".join(failed_cert_install),
        )


def _certificate_install_letsencrypt(domains, force=False, no_checks=False):
    from yunohost.domain import domain_list, _assert_domain_exists

    if not os.path.exists(ACCOUNT_KEY_FILE):
        _generate_account_key()

    # If no domains given, consider all yunohost domains with self-signed
    # certificates
    if domains == []:
        for domain in domain_list()["domains"]:

            status = _get_status(domain)
            if status["CA_type"] != "selfsigned":
                continue

            domains.append(domain)

    # Else, validate that yunohost knows the domains given
    else:
        for domain in domains:
            _assert_domain_exists(domain)

            # Is it self-signed?
            status = _get_status(domain)
            if not force and status["CA_type"] != "selfsigned":
                raise YunohostValidationError(
                    "certmanager_domain_cert_not_selfsigned", domain=domain
                )

    # Actual install steps
    failed_cert_install = []
    for domain in domains:

        if not no_checks:
            try:
                _check_domain_is_ready_for_ACME(domain)
            except Exception as e:
                logger.error(e)
                continue

        logger.info("Now attempting install of certificate for domain %s!", domain)

        operation_logger = OperationLogger(
            "letsencrypt_cert_install",
            [("domain", domain)],
            args={"force": force, "no_checks": no_checks},
        )
        operation_logger.start()

        try:
            _fetch_and_enable_new_certificate(domain, no_checks=no_checks)
        except Exception as e:
            msg = f"Certificate installation for {domain} failed !\nException: {e}"
            logger.error(msg)
            operation_logger.error(msg)
            if no_checks:
                logger.error(
                    f"Please consider checking the 'DNS records' (basic) and 'Web' categories of the diagnosis to check for possible issues that may prevent installing a Let's Encrypt certificate on domain {domain}."
                )
            failed_cert_install.append(domain)
        else:
            logger.success(m18n.n("certmanager_cert_install_success", domain=domain))

            operation_logger.success()

    if failed_cert_install:
        raise YunohostError(
            "certmanager_cert_install_failed", domains=",".join(failed_cert_install)
        )


def certificate_renew(domains, force=False, no_checks=False, email=False):
    """
    Renew Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domains    -- Domains for which to renew the certificates
        force      -- Ignore the validity threshold (15 days)
        no-check   -- Disable some checks about the reachability of web server
                      before attempting the renewing
        email      -- Emails root if some renewing failed
    """

    from yunohost.domain import domain_list, _assert_domain_exists

    # If no domains given, consider all yunohost domains with Let's Encrypt
    # certificates
    if domains == []:
        for domain in domain_list()["domains"]:

            # Does it have a Let's Encrypt cert?
            status = _get_status(domain)
            if status["CA_type"] != "letsencrypt":
                continue

            # Does it expire soon?
            if status["validity"] > VALIDITY_LIMIT and not force:
                continue

            # Check ACME challenge configured for given domain
            if not _check_acme_challenge_configuration(domain):
                logger.warning(
                    m18n.n("certmanager_acme_not_configured_for_domain", domain=domain)
                )
                continue

            domains.append(domain)

        if len(domains) == 0 and not email:
            logger.info("No certificate needs to be renewed.")

    # Else, validate the domain list given
    else:
        for domain in domains:

            # Is it in Yunohost domain list?
            _assert_domain_exists(domain)

            status = _get_status(domain)

            # Does it expire soon?
            if status["validity"] > VALIDITY_LIMIT and not force:
                raise YunohostValidationError(
                    "certmanager_attempt_to_renew_valid_cert", domain=domain
                )

            # Does it have a Let's Encrypt cert?
            if status["CA_type"] != "letsencrypt":
                raise YunohostValidationError(
                    "certmanager_attempt_to_renew_nonLE_cert", domain=domain
                )

            # Check ACME challenge configured for given domain
            if not _check_acme_challenge_configuration(domain):
                raise YunohostValidationError(
                    "certmanager_acme_not_configured_for_domain", domain=domain
                )

    # Actual renew steps
    failed_cert_install = []
    for domain in domains:

        if not no_checks:
            try:
                _check_domain_is_ready_for_ACME(domain)
            except Exception as e:
                logger.error(e)
                if email:
                    logger.error("Sending email with details to root ...")
                    _email_renewing_failed(domain, e)
                continue

        logger.info("Now attempting renewing of certificate for domain %s !", domain)

        operation_logger = OperationLogger(
            "letsencrypt_cert_renew",
            [("domain", domain)],
            args={
                "force": force,
                "no_checks": no_checks,
                "email": email,
            },
        )
        operation_logger.start()

        try:
            _fetch_and_enable_new_certificate(domain, no_checks=no_checks)
        except Exception as e:
            import traceback
            from io import StringIO

            stack = StringIO()
            traceback.print_exc(file=stack)
            msg = f"Certificate renewing for {domain} failed!"
            if no_checks:
                msg += f"\nPlease consider checking the 'DNS records' (basic) and 'Web' categories of the diagnosis to check for possible issues that may prevent installing a Let's Encrypt certificate on domain {domain}."
            logger.error(msg)
            operation_logger.error(msg)
            logger.error(stack.getvalue())
            logger.error(str(e))

            failed_cert_install.append(domain)

            if email:
                logger.error("Sending email with details to root ...")
                _email_renewing_failed(domain, msg + "\n" + str(e), stack.getvalue())
        else:
            logger.success(m18n.n("certmanager_cert_renew_success", domain=domain))
            operation_logger.success()

    if failed_cert_install:
        raise YunohostError(
            "certmanager_cert_renew_failed", domains=",".join(failed_cert_install)
        )


#
# Back-end stuff                                                            #
#


def _email_renewing_failed(domain, exception_message, stack=""):
    from_ = f"certmanager@{domain} (Certificate Manager)"
    to_ = "root"
    subject_ = f"Certificate renewing attempt for {domain} failed!"

    logs = _tail(50, "/var/log/yunohost/yunohost-cli.log")
    message = f"""\
From: {from_}
To: {to_}
Subject: {subject_}


An attempt for renewing the certificate for domain {domain} failed with the following
error :

{exception_message}
{stack}

Here's the tail of /var/log/yunohost/yunohost-cli.log, which might help to
investigate :

{logs}

-- Certificate Manager
"""

    import smtplib

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(from_, [to_], message.encode("utf-8"))
    smtp.quit()


def _check_acme_challenge_configuration(domain):

    domain_conf = f"/etc/nginx/conf.d/{domain}.conf"
    return "include /etc/nginx/conf.d/acme-challenge.conf.inc" in read_file(domain_conf)


def _fetch_and_enable_new_certificate(domain, no_checks=False):

    if not os.path.exists(ACCOUNT_KEY_FILE):
        _generate_account_key()

    # Make sure tmp folder exists
    logger.debug("Making sure tmp folders exists...")

    if not os.path.exists(WEBROOT_FOLDER):
        os.makedirs(WEBROOT_FOLDER)

    if not os.path.exists(TMP_FOLDER):
        os.makedirs(TMP_FOLDER)

    _set_permissions(WEBROOT_FOLDER, "root", "www-data", 0o650)
    _set_permissions(TMP_FOLDER, "root", "root", 0o640)

    # Regen conf for dnsmasq if needed
    _regen_dnsmasq_if_needed()

    # Prepare certificate signing request
    logger.debug("Prepare key and certificate signing request (CSR) for %s...", domain)

    domain_key_file = f"{TMP_FOLDER}/{domain}.pem"
    _generate_key(domain_key_file)
    _set_permissions(domain_key_file, "root", "ssl-cert", 0o640)

    _prepare_certificate_signing_request(domain, domain_key_file, TMP_FOLDER)

    # Sign the certificate
    logger.debug("Now using ACME Tiny to sign the certificate...")

    domain_csr_file = f"{TMP_FOLDER}/{domain}.csr"

    try:
        signed_certificate = sign_certificate(
            ACCOUNT_KEY_FILE,
            domain_csr_file,
            WEBROOT_FOLDER,
            log=logger,
            disable_check=no_checks,
            CA=PRODUCTION_CERTIFICATION_AUTHORITY,
        )
    except ValueError as e:
        if "urn:acme:error:rateLimited" in str(e):
            raise YunohostError("certmanager_hit_rate_limit", domain=domain)
        else:
            logger.error(str(e))
            raise YunohostError("certmanager_cert_signing_failed")

    except Exception as e:
        logger.error(str(e))

        raise YunohostError("certmanager_cert_signing_failed")

    # Now save the key and signed certificate
    logger.debug("Saving the key and signed certificate...")

    # Create corresponding directory
    date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")

    new_cert_folder = f"{CERT_FOLDER}/{domain}-history/{date_tag}-letsencrypt"

    os.makedirs(new_cert_folder)

    _set_permissions(new_cert_folder, "root", "root", 0o655)

    # Move the private key
    domain_key_file_finaldest = os.path.join(new_cert_folder, "key.pem")
    shutil.move(domain_key_file, domain_key_file_finaldest)
    _set_permissions(domain_key_file_finaldest, "root", "ssl-cert", 0o640)

    # Write the cert
    domain_cert_file = os.path.join(new_cert_folder, "crt.pem")

    with open(domain_cert_file, "w") as f:
        f.write(signed_certificate)

    _set_permissions(domain_cert_file, "root", "ssl-cert", 0o640)

    _enable_certificate(domain, new_cert_folder)

    # Check the status of the certificate is now good
    status_style = _get_status(domain)["style"]

    if status_style != "success":
        raise YunohostError(
            "certmanager_certificate_fetching_or_enabling_failed", domain=domain
        )


def _prepare_certificate_signing_request(domain, key_file, output_folder):
    from OpenSSL import crypto  # lazy loading this module for performance reasons

    # Init a request
    csr = crypto.X509Req()

    # Set the domain
    csr.get_subject().CN = domain

    from yunohost.domain import domain_config_get

    # If XMPP is enabled for this domain, add xmpp-upload and muc subdomains
    # in subject alternate names
    if domain_config_get(domain, key="feature.xmpp.xmpp") == 1:
        subdomain = "xmpp-upload." + domain
        xmpp_records = (
            Diagnoser.get_cached_report(
                "dnsrecords", item={"domain": domain, "category": "xmpp"}
            ).get("data")
            or {}
        )
        sanlist = []
        for sub in ("xmpp-upload", "muc"):
            subdomain = sub + "." + domain
            if xmpp_records.get("CNAME:" + sub) == "OK":
                sanlist.append(("DNS:" + subdomain))
            else:
                logger.warning(
                    m18n.n(
                        "certmanager_warning_subdomain_dns_record",
                        subdomain=subdomain,
                        domain=domain,
                    )
                )

        if sanlist:
            csr.add_extensions(
                [
                    crypto.X509Extension(
                        b"subjectAltName",
                        False,
                        (", ".join(sanlist)).encode("utf-8"),
                    )
                ]
            )

    # Set the key
    with open(key_file, "rt") as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    csr.set_pubkey(key)

    # Sign the request
    csr.sign(key, "sha256")

    # Save the request in tmp folder
    csr_file = output_folder + domain + ".csr"
    logger.debug("Saving to %s.", csr_file)

    with open(csr_file, "wb") as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))


def _get_status(domain):

    import yunohost.domain

    cert_file = os.path.join(CERT_FOLDER, domain, "crt.pem")

    if not os.path.isfile(cert_file):
        raise YunohostError("certmanager_no_cert_file", domain=domain, file=cert_file)

    from OpenSSL import crypto  # lazy loading this module for performance reasons

    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
    except Exception as exception:
        import traceback

        traceback.print_exc(file=sys.stdout)
        raise YunohostError(
            "certmanager_cannot_read_cert",
            domain=domain,
            file=cert_file,
            reason=exception,
        )

    cert_subject = cert.get_subject().CN
    cert_issuer = cert.get_issuer().CN
    organization_name = cert.get_issuer().O
    valid_up_to = datetime.strptime(
        cert.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%SZ"
    )
    days_remaining = (valid_up_to - datetime.utcnow()).days

    self_signed_issuers = ["yunohost.org"] + yunohost.domain.domain_list()["domains"]

    # FIXME: is the .ca.cnf one actually used anywhere ? x_x
    conf = os.path.join(SSL_DIR, "openssl.ca.cnf")
    if os.path.exists(conf):
        self_signed_issuers.append(
            check_output(f"grep commonName_default {conf}").split()[-1]
        )
    conf = os.path.join(SSL_DIR, "openssl.cnf")
    if os.path.exists(conf):
        self_signed_issuers.append(
            check_output(f"grep commonName_default {conf}").split()[-1]
        )

    if cert_issuer in self_signed_issuers:
        CA_type = "selfsigned"
    elif organization_name == "Let's Encrypt":
        CA_type = "letsencrypt"
    else:
        CA_type = "other"

    if days_remaining <= 0:
        style = "danger"
        summary = "expired"
    elif CA_type == "selfsigned":
        style = "warning"
        summary = "selfsigned"
    elif days_remaining < VALIDITY_LIMIT:
        style = "warning"
        summary = "abouttoexpire"
    elif CA_type == "other":
        style = "success"
        summary = "ok"
    elif CA_type == "letsencrypt":
        style = "success"
        summary = "letsencrypt"
    else:
        # shouldnt happen, because CA_type can be only selfsigned, letsencrypt, or other
        style = ""
        summary = "wat"

    return {
        "domain": domain,
        "subject": cert_subject,
        "CA_name": cert_issuer,
        "CA_type": CA_type,
        "validity": days_remaining,
        "style": style,
        "summary": summary,
    }


#
# Misc small stuff ...                                                      #
#


def _generate_account_key():
    logger.debug("Generating account key ...")
    _generate_key(ACCOUNT_KEY_FILE)
    _set_permissions(ACCOUNT_KEY_FILE, "root", "root", 0o400)


def _generate_key(destination_path):
    from OpenSSL import crypto  # lazy loading this module for performance reasons

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, KEY_SIZE)

    with open(destination_path, "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def _set_permissions(path, user, group, permissions):
    chown(path, user, group)
    chmod(path, permissions)


def _enable_certificate(domain, new_cert_folder):
    logger.debug("Enabling the certificate for domain %s ...", domain)

    live_link = os.path.join(CERT_FOLDER, domain)

    # If a live link (or folder) already exists
    if os.path.exists(live_link):
        # If it's not a link ... expect if to be a folder
        if not os.path.islink(live_link):
            # Backup it and remove it
            _backup_current_cert(domain)
            shutil.rmtree(live_link)
        # Else if it's a link, simply delete it
        elif os.path.lexists(live_link):
            os.remove(live_link)

    os.symlink(new_cert_folder, live_link)

    logger.debug("Restarting services...")

    for service in ("postfix", "dovecot", "metronome"):
        # Ugly trick to not restart metronome if it's not installed
        if (
            service == "metronome"
            and os.system("dpkg --list | grep -q 'ii *metronome'") != 0
        ):
            continue
        _run_service_command("restart", service)

    if os.path.isfile("/etc/yunohost/installed"):
        # regen nginx conf to be sure it integrates OCSP Stapling
        # (We don't do this yet if postinstall is not finished yet)
        regen_conf(names=["nginx"])

    _run_service_command("reload", "nginx")

    from yunohost.hook import hook_callback

    hook_callback("post_cert_update", args=[domain])


def _backup_current_cert(domain):
    logger.debug("Backuping existing certificate for domain %s", domain)

    cert_folder_domain = os.path.join(CERT_FOLDER, domain)

    date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")
    backup_folder = f"{cert_folder_domain}-backups/{date_tag}"

    shutil.copytree(cert_folder_domain, backup_folder)


def _check_domain_is_ready_for_ACME(domain):

    from yunohost.domain import _get_parent_domain_of
    from yunohost.dns import _get_dns_zone_for_domain
    from yunohost.utils.dns import is_yunohost_dyndns_domain

    httpreachable = (
        Diagnoser.get_cached_report(
            "web", item={"domain": domain}, warn_if_no_cache=False
        )
        or {}
    )

    parent_domain = _get_parent_domain_of(domain, return_self=True)

    dnsrecords = (
        Diagnoser.get_cached_report(
            "dnsrecords",
            item={"domain": parent_domain, "category": "basic"},
            warn_if_no_cache=False,
        )
        or {}
    )

    base_dns_zone = _get_dns_zone_for_domain(domain)
    record_name = (
        domain.replace(f".{base_dns_zone}", "") if domain != base_dns_zone else "@"
    )

    # Stupid edge case for subdomains of ynh dyndns domains ...
    # ... related to the fact that we don't actually check subdomains for
    # dyndns domains because we assume that there's already the wildcard doing
    # the job, hence no "A:foobar" ... Instead, just check that the parent domain
    # is correctly configured.
    if is_yunohost_dyndns_domain(parent_domain):
        record_name = "@"

    A_record_status = dnsrecords.get("data", {}).get(f"A:{record_name}")
    AAAA_record_status = dnsrecords.get("data", {}).get(f"AAAA:{record_name}")

    # Fallback to wildcard in case no result yet for the DNS name?
    if not A_record_status:
        A_record_status = dnsrecords.get("data", {}).get("A:*")
    if not AAAA_record_status:
        AAAA_record_status = dnsrecords.get("data", {}).get("AAAA:*")

    if (
        not httpreachable
        or not dnsrecords.get("data")
        or (A_record_status, AAAA_record_status) == (None, None)
    ):
        raise YunohostValidationError(
            "certmanager_domain_not_diagnosed_yet", domain=domain
        )

    # Check if IP from DNS matches public IP
    # - 'MISSING' for IPv6 ain't critical for ACME
    # - IPv4 can be None assuming there's at least an IPv6, and viveversa
    #    - (the case where both are None is checked before)
    if not (
        A_record_status in [None, "OK"]
        and AAAA_record_status in [None, "OK", "MISSING"]
    ):
        raise YunohostValidationError(
            "certmanager_domain_dns_ip_differs_from_public_ip", domain=domain
        )

    # Check if domain seems to be accessible through HTTP?
    if not httpreachable.get("status") == "SUCCESS":
        raise YunohostValidationError(
            "certmanager_domain_http_not_working", domain=domain
        )


# FIXME / TODO : ideally this should not be needed. There should be a proper
# mechanism to regularly check the value of the public IP and trigger
# corresponding hooks (e.g. dyndns update and dnsmasq regen-conf)
def _regen_dnsmasq_if_needed():
    """
    Update the dnsmasq conf if some IPs are not up to date...
    """

    ipv4 = get_public_ip()
    ipv6 = get_public_ip(6)

    do_regen = False

    # For all domain files in DNSmasq conf...
    domainsconf = glob.glob("/etc/dnsmasq.d/*.*")
    for domainconf in domainsconf:

        # Look for the IP, it's in the lines with this format :
        # host-record=the.domain.tld,11.22.33.44
        for line in open(domainconf).readlines():
            if not line.startswith("host-record"):
                continue
            ip = line.strip().split(",")[-1]

            # Compared found IP to current IPv4 / IPv6
            #             IPv6                   IPv4
            if (":" in ip and ip != ipv6) or (ip != ipv4):
                do_regen = True
                break

        if do_regen:
            break

    if do_regen:
        regen_conf(["dnsmasq"])


def _name_self_CA():
    ca_conf = os.path.join(SSL_DIR, "openssl.ca.cnf")

    if not os.path.exists(ca_conf):
        logger.warning(m18n.n("certmanager_self_ca_conf_file_not_found", file=ca_conf))
        return ""

    with open(ca_conf) as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith("commonName_default"):
            return line.split()[2]

    logger.warning(m18n.n("certmanager_unable_to_parse_self_CA_name", file=ca_conf))
    return ""


def _tail(n, file_path):
    return check_output(f"tail -n {n} '{file_path}'")
