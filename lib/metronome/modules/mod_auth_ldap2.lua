-- vim:sts=4 sw=4

-- Metronome IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
-- Copyright (C) 2015 YUNOHOST.ORG
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--
-- https://github.com/YunoHost/yunohost-config-metronome/blob/unstable/lib/modules/mod_auth_ldap2.lua
-- adapted to use common LDAP store on Metronome

local ldap     = module:require 'ldap';
local new_sasl = require 'util.sasl'.new;
local jsplit   = require 'util.jid'.split;

local log = module._log

if not ldap then
    return;
end

function new_default_provider(host)
 local provider = { name = "ldap2" };
 log("debug", "initializing ldap2 authentication provider for host '%s'", host);

 function provider.test_password(username, password)
     return ldap.bind(username, password);
 end

 function provider.user_exists(username)
     local params = ldap.getparams()

     local filter = ldap.filter.combine_and(params.user.filter, params.user.usernamefield .. '=' .. username);
     if params.user.usernamefield == 'mail' then
         filter = ldap.filter.combine_and(params.user.filter, 'mail=' .. username .. '@*');
     end

     return ldap.singlematch {
         base   = params.user.basedn,
         filter = filter,
     };
 end

 function provider.get_password(username)
     return nil, "Passwords unavailable for LDAP.";
 end

 function provider.set_password(username, password)
     return nil, "Passwords unavailable for LDAP.";
 end

 function provider.create_user(username, password)
     return nil, "Account creation/modification not available with LDAP.";
 end

 function provider.get_sasl_handler(session)
     local testpass_authentication_profile = {
         session = session,
         plain_test = function(sasl, username, password, realm)
             return provider.test_password(username, password), true;
         end,
         order = { "plain_test" },
     };
     return new_sasl(module.host, testpass_authentication_profile);
 end

 function provider.is_admin(jid)
     local admin_config = ldap.getparams().admin;

     if not admin_config then
         return;
     end

     local ld       = ldap:getconnection();
     local username = jsplit(jid);
     local filter   = ldap.filter.combine_and(admin_config.filter, admin_config.namefield .. '=' .. username);

     return ldap.singlematch {
         base   = admin_config.basedn,
         filter = filter,
     };
 end

 return provider;
end

module:add_item("auth-provider", new_default_provider(module.host));
