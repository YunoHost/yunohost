# -*- coding: utf-8 -*-

""" License

    Copyright (C) 2016 YUNOHOST.ORG

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses

    yunohost_certificate.py

    Manage certificates, in particular Let's encrypt
"""

import os
import sys
import shutil
import pwd
import grp
import smtplib
import subprocess
import dns.resolver
import glob

from datetime import datetime

from yunohost.vendor.acme_tiny.acme_tiny import get_crt as sign_certificate

from yunohost.utils.error import YunohostError
from moulinette.utils.log import getActionLogger

from yunohost.utils.network import get_public_ip

from moulinette import m18n
from yunohost.app import app_ssowatconf
from yunohost.service import _run_service_command
from yunohost.regenconf import regen_conf
from yunohost.log import OperationLogger

logger = getActionLogger('yunohost.certmanager')

CERT_FOLDER = "/etc/yunohost/certs/"
TMP_FOLDER = "/tmp/acme-challenge-private/"
WEBROOT_FOLDER = "/tmp/acme-challenge-public/"

SELF_CA_FILE = "/etc/ssl/certs/ca-yunohost_crt.pem"
ACCOUNT_KEY_FILE = "/etc/yunohost/letsencrypt_account.pem"

SSL_DIR = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'

KEY_SIZE = 3072

VALIDITY_LIMIT = 15  # days

# For tests
STAGING_CERTIFICATION_AUTHORITY = "https://acme-staging.api.letsencrypt.org"
# For prod
PRODUCTION_CERTIFICATION_AUTHORITY = "https://acme-v02.api.letsencrypt.org"

INTERMEDIATE_CERTIFICATE_URL = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"

DNS_RESOLVERS = [
    # FFDN DNS resolvers
    # See https://www.ffdn.org/wiki/doku.php?id=formations:dns
    "80.67.169.12",    # FDN
    "80.67.169.40",    #
    "89.234.141.66",   # ARN
    "141.255.128.100",  # Aquilenet
    "141.255.128.101",
    "89.234.186.18",   # Grifon
    "80.67.188.188"   # LDN
]

#
# Front-end stuff                                                           #
#


def certificate_status(domain_list, full=False):
    """
    Print the status of certificate for given domains (all by default)

    Keyword argument:
        domain_list -- Domains to be checked
        full        -- Display more info about the certificates
    """

    import yunohost.domain

    # If no domains given, consider all yunohost domains
    if domain_list == []:
        domain_list = yunohost.domain.domain_list()['domains']
    # Else, validate that yunohost knows the domains given
    else:
        yunohost_domains_list = yunohost.domain.domain_list()['domains']
        for domain in domain_list:
            # Is it in Yunohost domain list?
            if domain not in yunohost_domains_list:
                raise YunohostError('certmanager_domain_unknown', domain=domain)

    certificates = {}

    for domain in domain_list:
        status = _get_status(domain)

        if not full:
            del status["subject"]
            del status["CA_name"]
            del status["ACME_eligible"]
            status["CA_type"] = status["CA_type"]["verbose"]
            status["summary"] = status["summary"]["verbose"]

        del status["domain"]
        certificates[domain] = status

    return {"certificates": certificates}


def certificate_install(domain_list, force=False, no_checks=False, self_signed=False, staging=False):
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
        _certificate_install_letsencrypt(
            domain_list, force, no_checks, staging)


def _certificate_install_selfsigned(domain_list, force=False):

    for domain in domain_list:

        operation_logger = OperationLogger('selfsigned_cert_install', [('domain', domain)],
                                           args={'force': force})

        # Paths of files and folder we'll need
        date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")
        new_cert_folder = "%s/%s-history/%s-selfsigned" % (
            CERT_FOLDER, domain, date_tag)

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

            if status["summary"]["code"] in ('good', 'great'):
                raise YunohostError('certmanager_attempt_to_replace_valid_cert', domain=domain)

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
            "openssl req -new -config %s -days 3650 -out %s -keyout %s -nodes -batch"
            % (conf_file, csr_file, key_file),
            "openssl ca -config %s -days 3650 -in %s -out %s -batch"
            % (conf_file, csr_file, crt_file),
        ]

        for command in commands:
            p = subprocess.Popen(
                command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            out, _ = p.communicate()

            if p.returncode != 0:
                logger.warning(out)
                raise YunohostError('domain_cert_gen_failed')
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

        if status and status["CA_type"]["code"] == "self-signed" and status["validity"] > 3648:
            logger.success(
                m18n.n("certmanager_cert_install_success_selfsigned", domain=domain))
            operation_logger.success()
        else:
            msg = "Installation of self-signed certificate installation for %s failed !" % (domain)
            logger.error(msg)
            operation_logger.error(msg)


def _certificate_install_letsencrypt(domain_list, force=False, no_checks=False, staging=False):
    import yunohost.domain

    if not os.path.exists(ACCOUNT_KEY_FILE):
        _generate_account_key()

    # If no domains given, consider all yunohost domains with self-signed
    # certificates
    if domain_list == []:
        for domain in yunohost.domain.domain_list()['domains']:

            status = _get_status(domain)
            if status["CA_type"]["code"] != "self-signed":
                continue

            domain_list.append(domain)

    # Else, validate that yunohost knows the domains given
    else:
        for domain in domain_list:
            yunohost_domains_list = yunohost.domain.domain_list()['domains']
            if domain not in yunohost_domains_list:
                raise YunohostError('certmanager_domain_unknown', domain=domain)

            # Is it self-signed?
            status = _get_status(domain)
            if not force and status["CA_type"]["code"] != "self-signed":
                raise YunohostError('certmanager_domain_cert_not_selfsigned', domain=domain)

    if staging:
        logger.warning(
            "Please note that you used the --staging option, and that no new certificate will actually be enabled !")

    # Actual install steps
    for domain in domain_list:

        operation_logger = OperationLogger('letsencrypt_cert_install', [('domain', domain)],
                                           args={'force': force, 'no_checks': no_checks,
                                                 'staging': staging})
        logger.info(
            "Now attempting install of certificate for domain %s!", domain)

        try:
            if not no_checks:
                _check_domain_is_ready_for_ACME(domain)

            operation_logger.start()

            _configure_for_acme_challenge(domain)
            _fetch_and_enable_new_certificate(domain, staging, no_checks=no_checks)
            _install_cron(no_checks=no_checks)

            logger.success(
                m18n.n("certmanager_cert_install_success", domain=domain))

            operation_logger.success()
        except Exception as e:
            _display_debug_information(domain)
            msg = "Certificate installation for %s failed !\nException: %s" % (domain, e)
            logger.error(msg)
            operation_logger.error(msg)


def certificate_renew(domain_list, force=False, no_checks=False, email=False, staging=False):
    """
    Renew Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domain_list -- Domains for which to renew the certificates
        force      -- Ignore the validity threshold (15 days)
        no-check   -- Disable some checks about the reachability of web server
                      before attempting the renewing
        email      -- Emails root if some renewing failed
    """

    import yunohost.domain

    # If no domains given, consider all yunohost domains with Let's Encrypt
    # certificates
    if domain_list == []:
        for domain in yunohost.domain.domain_list()['domains']:

            # Does it have a Let's Encrypt cert?
            status = _get_status(domain)
            if status["CA_type"]["code"] != "lets-encrypt":
                continue

            # Does it expire soon?
            if status["validity"] > VALIDITY_LIMIT and not force:
                continue

            # Check ACME challenge configured for given domain
            if not _check_acme_challenge_configuration(domain):
                logger.warning(m18n.n(
                    'certmanager_acme_not_configured_for_domain', domain=domain))
                continue

            domain_list.append(domain)

        if len(domain_list) == 0 and not email:
            logger.info("No certificate needs to be renewed.")

    # Else, validate the domain list given
    else:
        for domain in domain_list:

            # Is it in Yunohost dmomain list?
            if domain not in yunohost.domain.domain_list()['domains']:
                raise YunohostError('certmanager_domain_unknown', domain=domain)

            status = _get_status(domain)

            # Does it expire soon?
            if status["validity"] > VALIDITY_LIMIT and not force:
                raise YunohostError('certmanager_attempt_to_renew_valid_cert', domain=domain)

            # Does it have a Let's Encrypt cert?
            if status["CA_type"]["code"] != "lets-encrypt":
                raise YunohostError('certmanager_attempt_to_renew_nonLE_cert', domain=domain)

            # Check ACME challenge configured for given domain
            if not _check_acme_challenge_configuration(domain):
                raise YunohostError('certmanager_acme_not_configured_for_domain', domain=domain)

    if staging:
        logger.warning(
            "Please note that you used the --staging option, and that no new certificate will actually be enabled !")

    # Actual renew steps
    for domain in domain_list:

        operation_logger = OperationLogger('letsencrypt_cert_renew', [('domain', domain)],
                                           args={'force': force, 'no_checks': no_checks,
                                                 'staging': staging, 'email': email})

        logger.info(
            "Now attempting renewing of certificate for domain %s !", domain)

        try:
            if not no_checks:
                _check_domain_is_ready_for_ACME(domain)

            operation_logger.start()

            _fetch_and_enable_new_certificate(domain, staging, no_checks=no_checks)

            logger.success(
                m18n.n("certmanager_cert_renew_success", domain=domain))

            operation_logger.success()

        except Exception as e:
            import traceback
            from StringIO import StringIO
            stack = StringIO()
            traceback.print_exc(file=stack)
            msg = "Certificate renewing for %s failed !" % (domain)
            logger.error(msg)
            operation_logger.error(msg)
            logger.error(stack.getvalue())
            logger.error(str(e))

            if email:
                logger.error("Sending email with details to root ...")
                _email_renewing_failed(domain, e, stack.getvalue())

#
# Back-end stuff                                                            #
#


def _install_cron(no_checks=False):
    cron_job_file = "/etc/cron.daily/yunohost-certificate-renew"

    # we need to check if "--no-checks" isn't already put inside the existing
    # crontab, if it's the case it's probably because another domain needed it
    # at some point so we keep it
    if not no_checks and os.path.exists(cron_job_file):
        with open(cron_job_file, "r") as f:
            # no the best test in the world but except if we uses a shell
            # script parser I'm not expected a much more better way to do that
            no_checks = "--no-checks" in f.read()

    command = "yunohost domain cert-renew --email\n"

    if no_checks:
        # handle trailing "\n with ":-1"
        command = command[:-1] + " --no-checks\n"

    with open(cron_job_file, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(command)

    _set_permissions(cron_job_file, "root", "root", 0o755)


def _email_renewing_failed(domain, exception_message, stack):
    from_ = "certmanager@%s (Certificate Manager)" % domain
    to_ = "root"
    subject_ = "Certificate renewing attempt for %s failed!" % domain

    logs = _tail(50, "/var/log/yunohost/yunohost-cli.log")
    text = """
An attempt for renewing the certificate for domain %s failed with the following
error :

%s
%s

Here's the tail of /var/log/yunohost/yunohost-cli.log, which might help to
investigate :

%s

-- Certificate Manager

""" % (domain, exception_message, stack, logs)

    message = """\
From: %s
To: %s
Subject: %s

%s
""" % (from_, to_, subject_, text)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(from_, [to_], message)
    smtp.quit()


def _configure_for_acme_challenge(domain):

    nginx_conf_folder = "/etc/nginx/conf.d/%s.d" % domain
    nginx_conf_file = "%s/000-acmechallenge.conf" % nginx_conf_folder

    nginx_configuration = '''
location ^~ '/.well-known/acme-challenge/'
{
        default_type "text/plain";
        alias %s;
}
    ''' % WEBROOT_FOLDER

    # Check there isn't a conflicting file for the acme-challenge well-known
    # uri
    for path in glob.glob('%s/*.conf' % nginx_conf_folder):

        if path == nginx_conf_file:
            continue

        with open(path) as f:
            contents = f.read()

        if '/.well-known/acme-challenge' in contents:
            raise YunohostError('certmanager_conflicting_nginx_file', filepath=path)

    # Write the conf
    if os.path.exists(nginx_conf_file):
        logger.debug(
            "Nginx configuration file for ACME challenge already exists for domain, skipping.")
        return

    logger.debug(
        "Adding Nginx configuration file for Acme challenge for domain %s.", domain)

    with open(nginx_conf_file, "w") as f:
        f.write(nginx_configuration)

    # Assume nginx conf is okay, and reload it
    # (FIXME : maybe add a check that it is, using nginx -t, haven't found
    # any clean function already implemented in yunohost to do this though)
    _run_service_command("reload", "nginx")

    app_ssowatconf()


def _check_acme_challenge_configuration(domain):
    # Check nginx conf file exists
    nginx_conf_folder = "/etc/nginx/conf.d/%s.d" % domain
    nginx_conf_file = "%s/000-acmechallenge.conf" % nginx_conf_folder

    if not os.path.exists(nginx_conf_file):
        return False
    else:
        return True


def _fetch_and_enable_new_certificate(domain, staging=False, no_checks=False):
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
    logger.debug(
        "Prepare key and certificate signing request (CSR) for %s...", domain)

    domain_key_file = "%s/%s.pem" % (TMP_FOLDER, domain)
    _generate_key(domain_key_file)
    _set_permissions(domain_key_file, "root", "ssl-cert", 0o640)

    _prepare_certificate_signing_request(domain, domain_key_file, TMP_FOLDER)

    # Sign the certificate
    logger.debug("Now using ACME Tiny to sign the certificate...")

    domain_csr_file = "%s/%s.csr" % (TMP_FOLDER, domain)

    if staging:
        certification_authority = STAGING_CERTIFICATION_AUTHORITY
    else:
        certification_authority = PRODUCTION_CERTIFICATION_AUTHORITY

    try:
        signed_certificate = sign_certificate(ACCOUNT_KEY_FILE,
                                              domain_csr_file,
                                              WEBROOT_FOLDER,
                                              log=logger,
                                              disable_check=no_checks,
                                              CA=certification_authority)
    except ValueError as e:
        if "urn:acme:error:rateLimited" in str(e):
            raise YunohostError('certmanager_hit_rate_limit', domain=domain)
        else:
            logger.error(str(e))
            _display_debug_information(domain)
            raise YunohostError('certmanager_cert_signing_failed')

    except Exception as e:
        logger.error(str(e))

        raise YunohostError('certmanager_cert_signing_failed')

    import requests  # lazy loading this module for performance reasons
    try:
        intermediate_certificate = requests.get(INTERMEDIATE_CERTIFICATE_URL, timeout=30).text
    except requests.exceptions.Timeout as e:
        raise YunohostError('certmanager_couldnt_fetch_intermediate_cert')

    # Now save the key and signed certificate
    logger.debug("Saving the key and signed certificate...")

    # Create corresponding directory
    date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")

    if staging:
        folder_flag = "staging"
    else:
        folder_flag = "letsencrypt"

    new_cert_folder = "%s/%s-history/%s-%s" % (
        CERT_FOLDER, domain, date_tag, folder_flag)

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
        f.write(intermediate_certificate)

    _set_permissions(domain_cert_file, "root", "ssl-cert", 0o640)

    if staging:
        return

    _enable_certificate(domain, new_cert_folder)

    # Check the status of the certificate is now good
    status_summary = _get_status(domain)["summary"]

    if status_summary["code"] != "great":
        raise YunohostError('certmanager_certificate_fetching_or_enabling_failed', domain=domain)


def _prepare_certificate_signing_request(domain, key_file, output_folder):
    from OpenSSL import crypto  # lazy loading this module for performance reasons
    # Init a request
    csr = crypto.X509Req()

    # Set the domain
    csr.get_subject().CN = domain

    # Set the key
    with open(key_file, 'rt') as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    csr.set_pubkey(key)

    # Sign the request
    csr.sign(key, "sha256")

    # Save the request in tmp folder
    csr_file = output_folder + domain + ".csr"
    logger.debug("Saving to %s.", csr_file)

    with open(csr_file, "w") as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))


def _get_status(domain):

    cert_file = os.path.join(CERT_FOLDER, domain, "crt.pem")

    if not os.path.isfile(cert_file):
        raise YunohostError('certmanager_no_cert_file', domain=domain, file=cert_file)

    from OpenSSL import crypto  # lazy loading this module for performance reasons
    try:
        cert = crypto.load_certificate(
            crypto.FILETYPE_PEM, open(cert_file).read())
    except Exception as exception:
        import traceback
        traceback.print_exc(file=sys.stdout)
        raise YunohostError('certmanager_cannot_read_cert', domain=domain, file=cert_file, reason=exception)

    cert_subject = cert.get_subject().CN
    cert_issuer = cert.get_issuer().CN
    valid_up_to = datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
    days_remaining = (valid_up_to - datetime.utcnow()).days

    if cert_issuer == _name_self_CA():
        CA_type = {
            "code": "self-signed",
            "verbose": "Self-signed",
        }

    elif cert_issuer.startswith("Let's Encrypt"):
        CA_type = {
            "code": "lets-encrypt",
            "verbose": "Let's Encrypt",
        }

    elif cert_issuer.startswith("Fake LE"):
        CA_type = {
            "code": "fake-lets-encrypt",
            "verbose": "Fake Let's Encrypt",
        }

    else:
        CA_type = {
            "code": "other-unknown",
            "verbose": "Other / Unknown",
        }

    if days_remaining <= 0:
        status_summary = {
            "code": "critical",
            "verbose": "CRITICAL",
        }

    elif CA_type["code"] in ("self-signed", "fake-lets-encrypt"):
        status_summary = {
            "code": "warning",
            "verbose": "WARNING",
        }

    elif days_remaining < VALIDITY_LIMIT:
        status_summary = {
            "code": "attention",
            "verbose": "About to expire",
        }

    elif CA_type["code"] == "other-unknown":
        status_summary = {
            "code": "good",
            "verbose": "Good",
        }

    elif CA_type["code"] == "lets-encrypt":
        status_summary = {
            "code": "great",
            "verbose": "Great!",
        }

    else:
        status_summary = {
            "code": "unknown",
            "verbose": "Unknown?",
        }

    try:
        _check_domain_is_ready_for_ACME(domain)
        ACME_eligible = True
    except:
        ACME_eligible = False

    return {
        "domain": domain,
        "subject": cert_subject,
        "CA_name": cert_issuer,
        "CA_type": CA_type,
        "validity": days_remaining,
        "summary": status_summary,
        "ACME_eligible": ACME_eligible
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

    with open(destination_path, "w") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def _set_permissions(path, user, group, permissions):
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)
    os.chmod(path, permissions)


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
        _run_service_command("restart", service)

    if os.path.isfile('/etc/yunohost/installed'):
        # regen nginx conf to be sure it integrates OCSP Stapling
        # (We don't do this yet if postinstall is not finished yet)
        regen_conf(names=['nginx'])

    _run_service_command("reload", "nginx")

    from yunohost.hook import hook_callback
    hook_callback('post_cert_update', args=[domain])


def _backup_current_cert(domain):
    logger.debug("Backuping existing certificate for domain %s", domain)

    cert_folder_domain = os.path.join(CERT_FOLDER, domain)

    date_tag = datetime.utcnow().strftime("%Y%m%d.%H%M%S")
    backup_folder = "%s-backups/%s" % (cert_folder_domain, date_tag)

    shutil.copytree(cert_folder_domain, backup_folder)


def _check_domain_is_ready_for_ACME(domain):
    public_ip = get_public_ip()

    # Check if IP from DNS matches public IP
    if not _dns_ip_match_public_ip(public_ip, domain):
        raise YunohostError('certmanager_domain_dns_ip_differs_from_public_ip', domain=domain)

    # Check if domain seems to be accessible through HTTP?
    if not _domain_is_accessible_through_HTTP(public_ip, domain):
        raise YunohostError('certmanager_domain_http_not_working', domain=domain)


def _get_dns_ip(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = DNS_RESOLVERS
        answers = resolver.query(domain, "A")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        raise YunohostError('certmanager_error_no_A_record', domain=domain)

    return str(answers[0])


def _dns_ip_match_public_ip(public_ip, domain):
    return _get_dns_ip(domain) == public_ip


def _domain_is_accessible_through_HTTP(ip, domain):
    import requests  # lazy loading this module for performance reasons
    try:
        requests.head("http://" + ip, headers={"Host": domain}, timeout=10)
    except requests.exceptions.Timeout as e:
        logger.warning(m18n.n('certmanager_http_check_timeout', domain=domain, ip=ip))
        return False
    except Exception as e:
        logger.debug("Couldn't reach domain '%s' by requesting this ip '%s' because: %s" % (domain, ip, e))
        return False

    return True


def _get_local_dns_ip(domain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.query(domain, "A")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        logger.warning("Failed to resolved domain '%s' locally", domain)
        return None

    return str(answers[0])


def _display_debug_information(domain):
    dns_ip = _get_dns_ip(domain)
    public_ip = get_public_ip()
    local_dns_ip = _get_local_dns_ip(domain)

    logger.warning("""\
Debug information:
 - domain ip from DNS        %s
 - domain ip from local DNS  %s
 - public ip of the server   %s
""", dns_ip, local_dns_ip, public_ip)


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
        # address=/the.domain.tld/11.22.33.44
        for line in open(domainconf).readlines():
            if not line.startswith("address"):
                continue
            ip = line.strip().split("/")[2]

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
        logger.warning(m18n.n('certmanager_self_ca_conf_file_not_found', file=ca_conf))
        return ""

    with open(ca_conf) as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith("commonName_default"):
            return line.split()[2]

    logger.warning(m18n.n('certmanager_unable_to_parse_self_CA_name', file=ca_conf))
    return ""


def _tail(n, file_path):
    stdin, stdout = os.popen2("tail -n %s '%s'" % (n, file_path))

    stdin.close()

    lines = stdout.readlines()
    stdout.close()

    return "".join(lines)
