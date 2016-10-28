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

"""

""" yunohost_certificate.py

    Manage certificates, in particular Let's encrypt
"""

import os
import sys
import errno
import requests
import shutil
import pwd
import grp
import json
import smtplib

from OpenSSL   import crypto
from datetime  import datetime
from tabulate  import tabulate
from acme_tiny import get_crt   as sign_certificate

from moulinette.core      import MoulinetteError
from moulinette.utils.log import getActionLogger
import yunohost.domain
from yunohost.service     import _run_service_command
from yunohost.app         import app_setting, app_ssowatconf


logger = getActionLogger('yunohost.certmanager')

# Misc stuff we need

cert_folder      = "/etc/yunohost/certs/"
tmp_folder       = "/tmp/acme-challenge-private/"
webroot_folder   = "/tmp/acme-challenge-public/"

selfCA_file      = "/etc/ssl/certs/ca-yunohost_crt.pem"
account_key_file = "/etc/yunohost/letsencrypt_account.pem"

key_size       = 2048

validity_limit = 15 # days

# For tests
#certification_authority = "https://acme-staging.api.letsencrypt.org"
# For prod
certification_authority = "https://acme-v01.api.letsencrypt.org"

intermediate_certificate_url = "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem"

###############################################################################
#   Front-end stuff                                                           #
###############################################################################

# Status

def certificate_status(auth, domainList, full = False):
    """
    Print the status of certificate for given domains (all by default)

    Keyword argument:
        domainList -- Domains to be checked
        full       -- Display more info about the certificates
    """

    # If no domains given, consider all yunohost domains
    if (domainList == []) : domainList = yunohost.domain.domain_list(auth)['domains']
    # Else, validate that yunohost knows the domains given
    else :
        for domain in domainList :
            # Is it in Yunohost dmomain list ?
            if domain not in yunohost.domain.domain_list(auth)['domains']:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))

    # Get status for each domain, and prepare display using tabulate
    if not full :
        headers = [ "Domain", "Certificate status", "Authority type", "Days remaining"]
    else :
        headers = [ "Domain", "Certificate subject", "Certificate status", "Authority type", "Authority name", "Days remaining"]
    lines = []
    for domain in domainList :
        status = _get_status(domain)

        line = []
        line.append(domain)
        if (full) : line.append(status["subject"])
        line.append(_summary_code_to_string(status["summaryCode"]))
        line.append(status["CAtype"])
        if (full) : line.append(status["CAname"])
        line.append(status["validity"])
        lines.append(line)

    print(tabulate(lines, headers=headers, tablefmt="simple", stralign="center"))


def certificate_install(auth, domainList, force=False, no_checks=False, self_signed=False) :
    """
    Install a Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domainList  -- Domains on which to install certificates
        force       -- Install even if current certificate is not self-signed
        no-check    -- Disable some checks about the reachability of web server
                       before attempting the install
        self-signed -- Instal self-signed certificates instead of Let's Encrypt
    """   
    if (self_signed) :
        certificate_install_selfsigned(domainList, force)
    else :
        certificate_install_letsencrypt(auth, domainList, force, no_checks)


# Install self-signed 

def certificate_install_selfsigned(domainList, force=False) :
        
    for domain in domainList : 

        # Check we ain't trying to overwrite a good cert !
        status = _get_status(domain)
        if (status != {}) and (status["summaryCode"] > 0) and (not force) :
            raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_replace_valid_cert', domain=domain))


        cert_folder_domain = cert_folder+"/"+domain

        # Create cert folder if it does not exists yet
        try: 
            os.listdir(cert_folder_domain)
        except OSError: 
            os.makedirs(cert_folder_domain)

        # Get serial
        ssl_dir = '/usr/share/yunohost/yunohost-config/ssl/yunoCA'
        with open('%s/serial' % ssl_dir, 'r') as f:
            serial = f.readline().rstrip()

        # FIXME : should refactor this to avoid so many os.system() calls...
        # We should be able to do all this using OpenSSL.crypto and os/shutil
        command_list = [
            'cp %s/openssl.cnf %s'                               % (ssl_dir, cert_folder_domain),
            'sed -i "s/yunohost.org/%s/g" %s/openssl.cnf'        % (domain, cert_folder_domain),
            'openssl req -new -config %s/openssl.cnf -days 3650 -out %s/certs/yunohost_csr.pem -keyout %s/certs/yunohost_key.pem -nodes -batch'
            % (cert_folder_domain, ssl_dir, ssl_dir),
            'openssl ca -config %s/openssl.cnf -days 3650 -in %s/certs/yunohost_csr.pem -out %s/certs/yunohost_crt.pem -batch'
            % (cert_folder_domain, ssl_dir, ssl_dir),
            'ln -s /etc/ssl/certs/ca-yunohost_crt.pem %s/ca.pem' % cert_folder_domain,
            'cp %s/certs/yunohost_key.pem    %s/key.pem'         % (ssl_dir, cert_folder_domain),
            'cp %s/newcerts/%s.pem %s/crt.pem'                   % (ssl_dir, serial, cert_folder_domain),
            'cat %s/ca.pem >> %s/crt.pem'                        % (cert_folder_domain, cert_folder_domain)
        ]

        for command in command_list:
            if os.system(command) != 0:
                raise MoulinetteError(errno.EIO, m18n.n('certmanager_domain_cert_gen_failed'))

        _set_permissions(cert_folder_domain,                "root", "root",      0755);
        _set_permissions(cert_folder_domain+"/key.pem",     "root", "metronome", 0640);
        _set_permissions(cert_folder_domain+"/crt.pem",     "root", "metronome", 0640);
        _set_permissions(cert_folder_domain+"/openssl.cnf", "root", "root",      0600);



# Install ACME / Let's Encrypt certificate

def certificate_install_letsencrypt(auth, domainList, force=False, no_checks=False):


    if not os.path.exists(account_key_file) :
        _generate_account_key()

    # If no domains given, consider all yunohost domains with self-signed
    # certificates
    if (domainList == []) :
        for domain in yunohost.domain.domain_list(auth)['domains'] :

            # Is it self-signed ?
            status = _get_status(domain)
            if (status["CAtype"] != "Self-signed") : continue

            domainList.append(domain)

    # Else, validate that yunohost knows the domains given
    else :
        for domain in domainList :
            # Is it in Yunohost dmomain list ?
            if domain not in yunohost.domain.domain_list(auth)['domains']:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))

            # Is it self-signed ?
            status = _get_status(domain)
            if (not force) and (status["CAtype"] != "Self-signed") :
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_cert_not_selfsigned', domain=domain))


    # Actual install steps
    for domain in domainList :
            
        logger.info("Now attempting install of certificate for domain "+domain+" !")

        try : 

            if not no_checks : _check_domain_is_correctly_configured(domain)
            _backup_current_cert(domain)
            _configure_for_acme_challenge(auth, domain)
            _fetch_and_enable_new_certificate(domain)
            _install_cron()
            
            logger.success(m18n.n("certmanager_cert_install_success", domain=domain))
 
        except Exception as e :
           
            logger.error("Certificate installation for "+domain+" failed !")
            logger.error(str(e))


# Renew


def certificate_renew(auth, domainList, force=False, no_checks=False, email=False):
    """
    Renew Let's Encrypt certificate for given domains (all by default)

    Keyword argument:
        domainList -- Domains for which to renew the certificates
        force      -- Ignore the validity threshold (15 days)
        no-check   -- Disable some checks about the reachability of web server
                      before attempting the renewing
        email      -- Emails root if some renewing failed
    """

    # If no domains given, consider all yunohost domains with Let's Encrypt
    # certificates
    if (domainList == []) :
        for domain in yunohost.domain.domain_list(auth)['domains'] :

            # Does it has a Let's Encrypt cert ?
            status = _get_status(domain)
            if (status["CAtype"] != "Let's Encrypt") : continue

            # Does it expires soon ?
            if (force) or (status["validity"] <= validity_limit) :
                domainList.append(domain)

        if (len(domainList) == 0) :
            logger.info("No certificate needs to be renewed.")

    # Else, validate the domain list given
    else :
        for domain in domainList :

            # Is it in Yunohost dmomain list ?
            if domain not in yunohost.domain.domain_list(auth)['domains']:
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_unknown', domain=domain))
            
            status = _get_status(domain)

            # Does it expires soon ?
            if not ((force) or (status["validity"] <= validity_limit)) :
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_renew_valid_cert', domain=domain))


            # Does it has a Let's Encrypt cert ?
            if (status["CAtype"] != "Let's Encrypt") :
                raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_attempt_to_renew_nonLE_cert', domain=domain))


    # Actual renew steps
    for domain in domainList :
        
        logger.info("Now attempting renewing of certificate for domain "+domain+" !")

        try : 

            if not no_checks : _check_domain_is_correctly_configured(domain)
            _backup_current_cert(domain)
            _fetch_and_enable_new_certificate(domain)

            logger.success(m18n.n("certmanager_cert_renew_success", domain=domain))
    
        except Exception as e :
           
            logger.error("Certificate renewing for "+domain+" failed !")
            logger.error(str(e))

            if (email) :
                logger.error("Sending email with details to root ...")
                _email_renewing_failed(domain, e)
            




###############################################################################
#   Back-end stuff                                                            #
###############################################################################

def _install_cron() :

    cron_job_file = "/etc/cron.weekly/certificateRenewer"

    with open(cron_job_file, "w") as f :

        f.write("#!/bin/bash\n")
        f.write("yunohost domain cert-renew --email\n")

    _set_permissions(cron_job_file, "root", "root", 0755);

def _email_renewing_failed(domain, e) :

    from_    = "certmanager@"+domain+" (Certificate Manager)"
    to_      = "root"
    subject_ = "Certificate renewing attempt for "+domain+" failed!"

    exceptionMessage = str(e)
    logs = _tail(50, "/var/log/yunohost/yunohost-cli.log")
    text     = """
At attempt for renewing the certificate for domain %s failed with the following
error :

%s

Here's the tail of /var/log/yunohost/yunohost-cli.log, which might help to
investigate :

%s

-- Certificate Manager

""" % (domain, exceptionMessage, logs)

    message = """
From: %s
To: %s
Subject: %s

%s
""" % (from_, to_, subject_, text)

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(from_, [ to_ ], message)
    smtp.quit()
 


def _configure_for_acme_challenge(auth, domain) :

    nginx_conf_file = "/etc/nginx/conf.d/"+domain+".d/000-acmechallenge.conf"

    nginx_configuration = '''
location '/.well-known/acme-challenge'
{
        default_type "text/plain";
        alias        '''+webroot_folder+''';
}
    '''

    # Write the conf
    if os.path.exists(nginx_conf_file) :
        logger.info("Nginx configuration file for ACME challenge already exists for domain, skipping.")
    else :
        logger.info("Adding Nginx configuration file for Acme challenge for domain " + domain + ".")
        with open(nginx_conf_file, "w") as f :
            f.write(nginx_configuration)

        # Assume nginx conf is okay, and reload it
        # (FIXME : maybe add a check that it is, using nginx -t, haven't found
        # any clean function already implemented in yunohost to do this though)
        _run_service_command("reload", "nginx")

        app_ssowatconf(auth)

def _fetch_and_enable_new_certificate(domain) :

    # Make sure tmp folder exists
    logger.debug("Making sure tmp folders exists...")

    if not (os.path.exists(webroot_folder)) : os.makedirs(webroot_folder)
    if not (os.path.exists(tmp_folder))     : os.makedirs(tmp_folder)
    _set_permissions(webroot_folder, "root", "www-data", 0650);
    _set_permissions(tmp_folder,     "root", "root",     0640);

    # Prepare certificate signing request
    logger.info("Prepare key and certificate signing request (CSR) for "+domain+"...")

    domain_key_file = tmp_folder+"/"+domain+".pem"
    _generate_key(domain_key_file)
    _set_permissions(domain_key_file, "root", "metronome", 0640);

    _prepare_certificate_signing_request(domain, domain_key_file, tmp_folder)

    # Sign the certificate
    logger.info("Now using ACME Tiny to sign the certificate...")

    domain_csr_file  = tmp_folder+"/"+domain+".csr"

    signed_certificate = sign_certificate(account_key_file,
                                          domain_csr_file,
                                          webroot_folder,
                                          log=logger,
                                          CA=certification_authority)
    intermediate_certificate = requests.get(intermediate_certificate_url).text

    # Now save the key and signed certificate
    logger.info("Saving the key and signed certificate...")

    # Create corresponding directory
    date_tag = datetime.now().strftime("%Y%m%d.%H%M%S")
    new_cert_folder = cert_folder+"/" + domain + "." + date_tag
    os.makedirs(new_cert_folder)
    _set_permissions(new_cert_folder, "root", "root", 0655);

    # Move the private key
    shutil.move(domain_key_file, new_cert_folder+"/key.pem")

    # Write the cert
    domain_cert_file = new_cert_folder+"/crt.pem"
    with open(domain_cert_file, "w") as f :
        f.write(signed_certificate)
        f.write(intermediate_certificate)
    _set_permissions(domain_cert_file, "root", "metronome", 0640);



    logger.info("Enabling the new certificate...")

    # Replace (if necessary) the link or folder for live cert
    live_link = cert_folder+"/"+domain

    if not os.path.islink(live_link) :
        shutil.rmtree(live_link) # Well, yep, hopefully that's not too dangerous (directory should have been backuped before calling this command)
    elif os.path.lexists(live_link) :
        os.remove(live_link)

    os.symlink(new_cert_folder, live_link)

    # Check the status of the certificate is now good

    statusSummaryCode = _get_status(domain)["summaryCode"]
    if (statusSummaryCode < 20) :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_certificate_fetching_or_enabling_failed', domain=domain))


    logger.info("Restarting services...")

    for s in [ "nginx", "postfix", "dovecot", "metronome" ] :
        _run_service_command("restart", s)


def _prepare_certificate_signing_request(domain, key_file, output_folder) :

    # Init a request
    csr = crypto.X509Req()

    # Set the domain
    csr.get_subject().CN = domain

    # Set the key
    with open(key_file, 'rt') as f :
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
    csr.set_pubkey(key)

    # Sign the request
    csr.sign(key, "sha256")

    # Save the request in tmp folder
    csr_file = output_folder+domain+".csr"
    logger.info("Saving to "+csr_file+" .")
    with open(csr_file, "w") as f :
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))


def _get_status(domain) :

    cert_file = cert_folder+"/"+domain+"/crt.pem"

    if (not os.path.isfile(cert_file)) : return {}

    try :
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(cert_file).read())
    except :
        raise MoulinetteError(errno.EINVAL,  m18n.n('certmanager_cannot_read_cert', domain=domain, file=cert_file))

    certSubject = cert.get_subject().CN
    certIssuer = cert.get_issuer().CN
    validUpTo = datetime.strptime(cert.get_notAfter(),"%Y%m%d%H%M%SZ")
    daysRemaining = (validUpTo - datetime.now()).days

    CAtype = None
    if (certIssuer == _name_selfCA()) :
        CAtype = "Self-signed"
    elif (certIssuer.startswith("Let's Encrypt")) :
        CAtype = "Let's Encrypt"
    elif (certIssuer.startswith("Fake LE")) :
        CAtype = "Fake Let's Encrypt"
    else :
        CAtype = "Other / Unknown"

    # Unknown by default
    statusSummaryCode = 0
    # Critical
    if (daysRemaining <= 0) :                                            statusSummaryCode = -30
    # Warning, self-signed, browser will display a warning discouraging visitors to enter website
    elif (CAtype == "Self-signed") or (CAtype == "Fake Let's Encrypt") : statusSummaryCode = -20
    # Attention, certificate will expire soon (should be renewed automatically if Let's Encrypt)
    elif (daysRemaining < validity_limit) :                              statusSummaryCode = -10
    # CA not known, but still a valid certificate, so okay !
    elif (CAtype == "Other / Unknown") :                                 statusSummaryCode =  10
    # Let's Encrypt, great !
    elif (CAtype == "Let's Encrypt") :                                   statusSummaryCode =  20

    return { "domain"      : domain,
             "subject"     : certSubject,
             "CAname"      : certIssuer,
             "CAtype"      : CAtype,
             "validity"    : daysRemaining,
             "summaryCode" : statusSummaryCode
           }

###############################################################################
#   Misc small stuff ...                                                      #
###############################################################################

def _generate_account_key() :

    logger.info("Generating account key ...")
    _generate_key(account_key_file)
    _set_permissions(account_key_file, "root", "root", 0400)

def _generate_key(destinationPath) :

    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, key_size)

    with open(destinationPath, "w") as f :
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

def _set_permissions(path, user, group, permissions) :

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid

    os.chown(path, uid, gid)
    os.chmod(path, permissions)

def _backup_current_cert(domain):

    logger.info("Backuping existing certificate for domain "+domain)

    cert_folder_domain = cert_folder+"/"+domain

    dateTag = datetime.now().strftime("%Y%m%d.%H%M%S")
    backup_folder = cert_folder_domain+"-backup-"+dateTag

    shutil.copytree(cert_folder_domain, backup_folder)


def _check_domain_is_correctly_configured(domain) :

    public_ip = yunohost.domain.get_public_ip()

    # Check if IP from DNS matches public IP
    if not _dns_ip_match_public_ip(public_ip, domain) :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_domain_dns_ip_differs_from_public_ip', domain=domain))

    # Check if domain seems to be accessible through HTTP ?
    if not _domain_is_accessible_through_HTTP(public_ip, domain) :
        raise MoulinetteError(errno.EINVAL,  m18n.n('certmanager_domain_http_not_working', domain=domain))
        
def _dns_ip_match_public_ip(public_ip, domain) :

    try :
        r = requests.get("http://dns-api.org/A/"+domain)
    except :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_error_contacting_dns_api', api="dns-api.org"))
        
    if (r.text == "[{\"error\":\"NXDOMAIN\"}]") :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_no_A_dns_record', domain=domain))

    try :
        dns_ip = json.loads(r.text)[0]["value"]
    except :
        raise MoulinetteError(errno.EINVAL, m18n.n('certmanager_error_parsing_dns', domain=domain, value=r.text))

    if (dns_ip != public_ip) :
        return False
    else :
        return True

def _domain_is_accessible_through_HTTP(ip, domain) :

    try :
        requests.head("http://"+ip, headers = { "Host" : domain })
    except Exception :
        return False

    return True

def _summary_code_to_string(code) :

    if   (code <= -30) : return "CRITICAL"
    elif (code <= -20) : return "WARNING"
    elif (code <= -10) : return "Attention"
    elif (code <=   0) : return "Unknown?"
    elif (code <=  10) : return "Good"
    elif (code <=  20) : return "Great!"

    return "Unknown?"

def _name_selfCA() :

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(selfCA_file).read())
    return cert.get_subject().CN


def _tail(n, filePath):
  stdin,stdout = os.popen2("tail -n "+str(n)+" "+filePath)
  stdin.close()
  lines = stdout.readlines(); stdout.close()
  lines = "".join(lines)
  return lines
