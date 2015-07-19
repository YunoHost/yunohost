-- vim:sts=4 sw=4

-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--
-- http://code.google.com/p/prosody-modules/source/browse/mod_auth_ldap/mod_auth_ldap.lua
-- adapted to use common LDAP store

local ldap     = module:require 'ldap';
local new_sasl = require 'util.sasl'.new;
local jsplit   = require 'util.jid'.split;

if not ldap then
    return;
end

local provider = {}

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

function provider.get_sasl_handler()
    local testpass_authentication_profile = {
        plain_test = function(sasl, username, password, realm)
            return provider.test_password(username, password), true;
        end,
        mechanisms = { PLAIN = true },
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

module:provides("auth", provider);
