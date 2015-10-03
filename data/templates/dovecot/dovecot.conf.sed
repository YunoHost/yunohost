# 2.1.7: /etc/dovecot/dovecot.conf
# OS: Linux 3.2.0-3-686-pae i686 Debian wheezy/sid ext4
listen = *, ::
auth_mechanisms = plain login
login_greeting = Dovecot ready!!
mail_gid = 8
mail_home = /var/mail/%n
mail_location = maildir:/var/mail/%n
mail_uid = 500
passdb {
  args = /etc/dovecot/dovecot-ldap.conf
  driver = ldap
}
protocols = imap sieve
mail_plugins = $mail_plugins quota
service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
  unix_listener auth-master {
    group = mail
    mode = 0660
    user = vmail
  }
}

protocol sieve {
}

ssl_ca = </etc/ssl/certs/ca-yunohost_crt.pem
ssl_cert = </etc/ssl/certs/yunohost_crt.pem
ssl_key = </etc/ssl/private/yunohost_key.pem
ssl_protocols = !SSLv2 !SSLv3
userdb {
  args = /etc/dovecot/dovecot-ldap.conf
  driver = ldap
}
protocol imap {
  imap_client_workarounds =
  mail_plugins = $mail_plugins imap_quota antispam autocreate
}
protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  mail_plugins = quota sieve
  postmaster_address = postmaster@{{ main_domain }}
}

plugin {
  sieve = /var/mail/sievescript/%n/.dovecot.sieve
  sieve_dir = /var/mail/sievescript/%n/scripts/
  sieve_before = /etc/dovecot/global_script/
}

plugin {
  antispam_debug_target = syslog
  antispam_verbose_debug = 0
  antispam_backend = pipe
  antispam_trash = Trash
  antispam_spam = SPAM;Junk
  antispam_allow_append_to_spam = no
  antispam_pipe_program = /usr/bin/sa-learn-pipe.sh
  antispam_pipe_program_spam_arg = --spam
  antispam_pipe_program_notspam_arg = --ham
}

plugin {
  autocreate = Trash
  autocreate2 = Junk
  autosubscribe = Trash
  autosubscribe2 = Junk
}

plugin {
  quota = maildir:User quota
  quota_rule2 = SPAM:ignore
  quota_rule3 = Trash:ignore
}

plugin {
  quota_warning = storage=95%% quota-warning 95 %u
  quota_warning2 = storage=80%% quota-warning 80 %u
  quota_warning3 = -storage=100%% quota-warning below %u # user is no longer over quota
}

service quota-warning {
  executable = script /usr/bin/quota-warning.sh
  user = vmail
  unix_listener quota-warning {
  }
}
