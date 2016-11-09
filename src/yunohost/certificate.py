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
import errno
import shutil
import pwd
import grp
import smtplib
import requests

import dns.resolver

from OpenSSL import crypto
from datetime import datetime
from yunohost.vendor.acme_tiny.acme_tiny import get_crt as sign_certificate

from moulinette.core import MoulinetteError
from moulinette.utils.log import getActionLogger

import yunohost.domain

from yunohost.app import app_ssowatconf, app_list
from yunohost.service import _run_service_command


logger = getActionLogger('yunohost.certmanager')

CERT_FOLDER = "/etc/yunohost/certs/"
TMP_FOLDER = "/tmp/acme-challenge-private/"
WEBROOT_FOLDER = "/tmp/acme-challenge-public/"

SELF_CA_FILE = "/etc/ssl/certs/ca-yunohost_crt.pem"
ACCOUNT_KEY_FILE = "/etc/yunohost/letsencrypt_account.pem"

KEY_SIZE = 2048

VALIDITY_LIMIT = 15  # days

# For tests
#CERTIFICATION_AUTHORITY = "https://acme-staging.api.letsencrypt.org"
# For prod
CERTIFICATION_AUTHORITY = "https://acme-v01.api.letsencrypt.org"

INTERMEDIATE_CERTIFICATE_URL = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"

###############################################################################
#   Front-end stuff                                                           #
###############################################################################


def certificate_status(auth, domain_list, full=False):
    """
    Print the status of certificate for given domains (all by default)

    Keyword argument:
        domain_list -- Domains to be checked
        full        -- Display more info about the certificates
    """

    # Check if old letsencrypt_ynh is installed
    _check_old_letsencrypt_app()

    # If no domains given, consider all yunohost domains
    if domain_list == []:
        domain_list = yunohost.domain.domain_list(auth)['domains']
    # Else, validate that yunohost knows the domains given
    else:
        yunohost_domains_list = yunohost.domain.domain_list(auth)['domains']
        for domain in domain_list:
            # Is it in Yunohost domain list ?
            if domain not in yunohost_domains_list:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))

    certificates = {}

    for domain in domain_list:
        status = _get_status(domain)

        if not full:
            del status["subject"]
            del status["CA_name"]
            status["CA_type"] = status["CA_type"]["verbose"]
            status["summary"] = status["summary"]["verbose"]

        del status["domain"]
        certificates[domain] = status

    return { "certificates" : certificates }


def certificate_install(auth, domain_list, force=False, no_checks=False, self_signed=False):
   
    """
    Install a Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domain_list  -- Domains on which to install certificates
        force        -- Install even if current certificate is not self-signed
        no-check     -- Disable some checks about the reachability of web server
                       before attempting the install
        self-signed  -- Instal self-signed certificates instead of Let's Encrypt
    """

    # Check if old letsencrypt_ynh is installed
    _check_old_letsencrypt_app()
    

    if self_signed:
        certificate_install_selfsigned(domain_list, force)
    else:
        certificate_install_letsencrypt(auth, domain_list, force, no_checks)


def certificate_install_selfsigned(domain_list, force=False):
    for domain in domain_list:

        # Check we ain't trying to overwrite a good cert !
        status = _get_status(domain)

        if status and status["summary"]["code"] in ('good', 'great') and not force:
            raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_replace_valid_cert', domain=domain))

        cert_folder_domain = os.path.join(CERT_FOLDER, domain)

        if not os.path.exists(cert_folder_domain):
            os.makedirs(cert_folder_domain)

        # Get serial
        ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
        with open(os.path.join(ssl_dir, 'serial'), 'r') as f:
            serial = f.readline().rstrip()

        shutil.copyfile(os.path.join(ssl_dir, "openssl.cnf"), os.path.join(cert_folder_domain, "openssl.cnf"))

        # FIXME : should refactor this to avoid so many os.system() calls...
        # We should be able to do all this using OpenSSL.crypto and os/shutil
        command_list = [
            'sed -i "s/yunohost.org/%s/g" %s/openssl.cnf' % (domain, cert_folder_domain),
            'openssl req -new -config %s/openssl.cnf -days 3650 -out %s/certs/yunohost_csr.pem -keyout %s/certs/yunohost_key.pem -nodes -batch'
            % (cert_folder_domain, ssl_dir, ssl_dir),
            'openssl ca -config %s/openssl.cnf -days 3650 -in %s/certs/yunohost_csr.pem -out %s/certs/yunohost_crt.pem -batch'
            % (cert_folder_domain, ssl_dir, ssl_dir),
        ]

        for command in command_list:
            if os.system(command) != 0:
                raise MoulinetteError(errno.EIO, m18n.n('certmanager_domain_cert_gen_failed'))

        os.symlink('/etc/ssl/certs/ca-yunohost_crt.pem', os.path.join(cert_folder_domain, "ca.pem"))
        shutil.copyfile(os.path.join(ssl_dir, "certs", "yunohost_key.pem"), os.path.join(cert_folder_domain, "key.pem"))
        shutil.copyfile(os.path.join(ssl_dir, "newcerts", "%s.pem" % serial), os.path.join(cert_folder_domain, "crt.pem"))

        # append ca.pem at the end of crt.pem
        with open(os.path.join(cert_folder_domain, "ca.pem"), "r") as ca_pem:
            with open(os.path.join(cert_folder_domain, "crt.pem"), "a") as crt_pem:
                crt_pem.write("\n")
                crt_pem.write(ca_pem.read())

        _set_permissions(cert_folder_domain, "root", "root", 0755)
        _set_permissions(os.path.join(cert_folder_domain, "key.pem"), "root", "metronome", 0640)
        _set_permissions(os.path.join(cert_folder_domain, "crt.pem"), "root", "metronome", 0640)
        _set_permissions(os.path.join(cert_folder_domain, "openssl.cnf"), "root", "root", 0600)


def certificate_install_letsencrypt(auth, domain_list, force=False, no_checks=False):
    if not os.path.exists(ACCOUNT_KEY_FILE):
        _generate_account_key()

    # If no domains given, consider all yunohost domains with self-signed
    # certificates
    if domain_list == []:
        for domain in yunohost.domain.domain_list(auth)['domains']:

            status = _get_status(domain)
            if status["CA_type"]["code"] != "self-signed":
                continue

            domain_list.append(domain)

    # Else, validate that yunohost knows the domains given
    else:
        for domain in domain_list:
            yunohost_domains_list = yunohost.domain.domain_list(auth)['domains']
            if domain not in yunohost_domains_list:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))

            # Is it self-signed ?
            status = _get_status(domain)
            if not force and status["CA_type"]["code"] != "self-signed":
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_cert_not_selfsigned', domain=domain))

    # Actual install steps
    for domain in domain_list:

        logger.info("Now attempting install of certificate for domain %s!", domain)

        try:
            if not no_checks:
                _check_domain_is_correctly_configured(domain)

            _backup_current_cert(domain)
            _configure_for_acme_challenge(auth, domain)
            _fetch_and_enable_new_certificate(domain)
            _install_cron()

            logger.success(m18n.n("certmanager_cert_install_success", domain=domain))

        except Exception as e:
            logger.error("Certificate installation for %s failed !", domain)
            logger.error(str(e))


def certificate_renew(auth, domain_list, force=False, no_checks=False, email=False):
    """
    Renew Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domain_list -- Domains for which to renew the certificates
        force      -- Ignore the validity threshold (15 days)
        no-check   -- Disable some checks about the reachability of web server
                      before attempting the renewing
        email      -- Emails root if some renewing failed
    """

    # Check if old letsencrypt_ynh is installed
    _check_old_letsencrypt_app()

    # If no domains given, consider all yunohost domains with Let's Encrypt
    # certificates
    if domain_list == []:
        for domain in yunohost.domain.domain_list(auth)['domains']:

            # Does it has a Let's Encrypt cert ?
            status = _get_status(domain)
            if status["CA_type"]["code"] != "lets-encrypt":
                continue

            # Does it expires soon ?
            if force or status["validity"] <= VALIDITY_LIMIT:
                domain_list.append(domain)

        if len(domain_list) == 0:
            logger.info("No certificate needs to be renewed.")

    # Else, validate the domain list given
    else:
        for domain in domain_list:

            # Is it in Yunohost dmomain list ?
            if domain not in yunohost.domain.domain_list(auth)['domains']:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))

            status = _get_status(domain)

            # Does it expires soon ?
            if not force or status["validity"] <= VALIDITY_LIMIT:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_renew_valid_cert', domain=domain))

            # Does it has a Let's Encrypt cert ?
            if status["CA_type"]["code"] != "lets-encrypt":
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_renew_nonLE_cert', domain=domain))

    # Actual renew steps
    for domain in domain_list:
        logger.info("Now attempting renewing of certificate for domain %s !", domain)

        try:
            if not no_checks:
                _check_domain_is_correctly_configured(domain)
            _backup_current_cert(domain)
            _fetch_and_enable_new_certificate(domain)

            logger.success(m18n.n("certmanager_cert_renew_success", domain=domain))

        except Exception as e:
            import traceback
            from StringIO import StringIO
            stack = StringIO()
            traceback.print_exc(file=stack)
            logger.error("Certificate renewing for %s failed !", domain)
            logger.error(stack.getvalue())
            logger.error(str(e))

            if email:
                logger.error("Sending email with details to root ...")
                _email_renewing_failed(domain, e, stack.getvalue())


###############################################################################
#   Back-end stuff                                                            #
###############################################################################

def _check_old_letsencrypt_app():

    installedAppIds = [ app["id"] for app in yunohost.app.app_list(installed=True)["apps"] ]
    if ("letsencrypt" not in installedAppIds) :
        return

    logger.warning(" ")
    logger.warning("Yunohost detected that the 'letsencrypt' app is installed, ")
    logger.warning("which conflits with the new certificate management features")
    logger.warning("directly integrated in Yunohost. If you wish to use these  ")
    logger.warning("new features, please run the following commands to migrate ")
    logger.warning("your installation :")
    logger.warning(" ")
    logger.warning("   yunohost app remove letsencrypt")
    logger.warning("   yunohost domain cert-install")
    logger.warning(" ")
    logger.warning("N.B. : this will attempt to re-install certificates for    ")
    logger.warning("all domains with a Let's Encrypt certificate or self-signed")
    logger.warning("certificate.")
    logger.warning(" ")
    
    raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_old_letsencrypt_app_detected'))

def _install_cron():
    cron_job_file = "/etc/cron.weekly/yunohost-certificate-renew"

    with open(cron_job_file, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("yunohost domain cert-renew --email\n")

    _set_permissions(cron_job_file, "root", "root", 0755)


def _email_renewing_failed(domain, exception_message, stack):
    from_ = "certmanager@%s (Certificate Manager)" % domain
    to_ = "root"
    subject_ = "Certificate renewing attempt for %s failed!" % domain

    logs = _tail(50, "/var/log/yunohost/yunohost-cli.log")
    text = """
At attempt for renewing the certificate for domain %s failed with the following
error :

%s
%s

Here's the tail of /var/log/yunohost/yunohost-cli.log, which might help to
investigate :

%s

-- Certificate Manager

""" % (domain, exception_message, stack, logs)

    message = """
From: %s
To: %s
Subject: %s

%s
""" % (from_, to_, subject_, text)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(from_, [to_], message)
    smtp.quit()


def _configure_for_acme_challenge(auth, domain):
    nginx_conf_file = "/etc/nginx/conf.d/%s.d/000-acmechallenge.conf" % domain

    nginx_configuration = '''
location '/.well-known/acme-challenge'
{
        default_type "text/plain";
        alias %s;
}
    ''' % WEBROOT_FOLDER

    # Write the conf
    if os.path.exists(nginx_conf_file):
        logger.info("Nginx configuration file for ACME challenge already exists for domain, skipping.")
        return

    logger.info("Adding Nginx configuration file for Acme challenge for domain %s.", domain)

    with open(nginx_conf_file, "w") as f:
        f.write(nginx_configuration)

    # Assume nginx conf is okay, and reload it
    # (FIXME : maybe add a check that it is, using nginx -t, haven't found
    # any clean function already implemented in yunohost to do this though)
    _run_service_command("reload", "nginx")

    app_ssowatconf(auth)


def _fetch_and_enable_new_certificate(domain):
    # Make sure tmp folder exists
    logger.debug("Making sure tmp folders exists...")

    if not os.path.exists(WEBROOT_FOLDER):
        os.makedirs(WEBROOT_FOLDER)

    if not os.path.exists(TMP_FOLDER):
        os.makedirs(TMP_FOLDER)

    _set_permissions(WEBROOT_FOLDER, "root", "www-data", 0650)
    _set_permissions(TMP_FOLDER, "root", "root", 0640)

    # Prepare certificate signing request
    logger.info("Prepare key and certificate signing request (CSR) for %s...", domain)

    domain_key_file = "%s/%s.pem" % (TMP_FOLDER, domain)
    _generate_key(domain_key_file)
    _set_permissions(domain_key_file, "root", "metronome", 0640)

    _prepare_certificate_signing_request(domain, domain_key_file, TMP_FOLDER)

    # Sign the certificate
    logger.info("Now using ACME Tiny to sign the certificate...")

    domain_csr_file = "%s/%s.csr" % (TMP_FOLDER, domain)

    signed_certificate = sign_certificate(ACCOUNT_KEY_FILE,
                                          domain_csr_file,
                                          WEBROOT_FOLDER,
                                          log=logger,
                                          CA=CERTIFICATION_AUTHORITY)

    intermediate_certificate = requests.get(INTERMEDIATE_CERTIFICATE_URL).text

    # Now save the key and signed certificate
    logger.info("Saving the key and signed certificate...")

    # Create corresponding directory
    date_tag = datetime.now().strftime("%Y%m%d.%H%M%S")

    new_cert_folder = "%s/%s.%s" % (CERT_FOLDER, domain, date_tag)
    os.makedirs(new_cert_folder)

    _set_permissions(new_cert_folder, "root", "root", 0655)

    # Move the private key
    shutil.move(domain_key_file, os.path.join(new_cert_folder, "key.pem"))

    # Write the cert
    domain_cert_file = os.path.join(new_cert_folder, "crt.pem")

    with open(domain_cert_file, "w") as f:
        f.write(signed_certificate)
        f.write(intermediate_certificate)

    _set_permissions(domain_cert_file, "root", "metronome", 0640)

    logger.info("Enabling the new certificate...")

    # Replace (if necessary) the link or folder for live cert
    live_link = os.path.join(CERT_FOLDER, domain)

    if not os.path.islink(live_link):
        shutil.rmtree(live_link)  # Well, yep, hopefully that's not too dangerous (directory should have been backuped before calling this command)

    elif os.path.lexists(live_link):
        os.remove(live_link)

    os.symlink(new_cert_folder, live_link)

    # Check the status of the certificate is now good
    status_summary = _get_status(domain)["summary"]

    if status_summary["code"] != "great":
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_certificate_fetching_or_enabling_failed', domain=domain))

    logger.info("Restarting services...")

    for service in ("postfix", "dovecot", "metronome"):
        _run_service_command("restart", service)

    _run_service_command("reload", "nginx")


def _prepare_certificate_signing_request(domain, key_file, output_folder):
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
    logger.info("Saving to %s.", csr_file)

    with open(csr_file, "w") as f:
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))


def _get_status(domain):
    cert_file = os.path.join(CERT_FOLDER, domain, "crt.pem")

    if not os.path.isfile(cert_file):
        return {}

    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
    except Exception as exception:
        import traceback
        traceback.print_exc(file=sys.stdout)
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_cannot_read_cert', domain=domain, file=cert_file, reason=exception))

    cert_subject = cert.get_subject().CN
    cert_issuer = cert.get_issuer().CN
    valid_up_to = datetime.strptime(cert.get_notAfter(), "%Y%m%d%H%M%SZ")
    days_remaining = (valid_up_to - datetime.now()).days

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

    elif CA_type["code"] in ("self-signed","fake-lets-encrypt"):
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

    return {
        "domain": domain,
        "subject": cert_subject,
        "CA_name": cert_issuer,
        "CA_type": CA_type,
        "validity": days_remaining,
        "summary": status_summary,
    }

###############################################################################
#   Misc small stuff ...                                                      #
###############################################################################


def _generate_account_key():
    logger.info("Generating account key ...")
    _generate_key(ACCOUNT_KEY_FILE)
    _set_permissions(ACCOUNT_KEY_FILE, "root", "root", 0400)


def _generate_key(destination_path):
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, KEY_SIZE)

    with open(destination_path, "w") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))


def _set_permissions(path, user, group, permissions):
    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)
    os.chmod(path, permissions)


def _backup_current_cert(domain):
    logger.info("Backuping existing certificate for domain %s", domain)

    cert_folder_domain = os.path.join(CERT_FOLDER, domain)

    date_tag = datetime.now().strftime("%Y%m%d.%H%M%S")
    backup_folder = "%s-backup-%s" % (cert_folder_domain, date_tag)

    shutil.copytree(cert_folder_domain, backup_folder)


def _check_domain_is_correctly_configured(domain):
    public_ip = yunohost.domain.get_public_ip()

    # Check if IP from DNS matches public IP
    if not _dns_ip_match_public_ip(public_ip, domain):
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_dns_ip_differs_from_public_ip', domain=domain))

    # Check if domain seems to be accessible through HTTP ?
    if not _domain_is_accessible_through_HTTP(public_ip, domain):
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_http_not_working', domain=domain))


def _dns_ip_match_public_ip(public_ip, domain):
    try:
        resolver = dns.resolver.Resolver()
        # These are FDN's DNS
        resolver.nameservers = [ "80.67.169.12", "80.67.169.40" ]
        answers = resolver.query(domain, "A")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_error_no_A_record', domain=domain))

    dns_ip = answers[0]

    return dns_ip == public_ip


def _domain_is_accessible_through_HTTP(ip, domain):
    try:
        r = requests.head("http://" + ip, headers={"Host": domain})
        # Check we got the ssowat header in the response
        if ("x-sso-wat" not in r.headers.keys()) :
            return False
    except Exception:
        return False

    return True


def _name_self_CA():
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(SELF_CA_FILE).read())
    return cert.get_subject().CN


def _tail(n, file_path):
    stdin, stdout = os.popen2("tail -n %s '%s'" % (n, file_path))

    stdin.close()

    lines = stdout.readlines()
    stdout.close()

    return "".join(lines)
