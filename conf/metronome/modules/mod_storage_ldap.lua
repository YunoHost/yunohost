-- vim:sts=4 sw=4

-- Metronome IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
-- Copyright (C) 2015 YUNOHOST.ORG
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.

----------------------------------------
-- Constants and such --
----------------------------------------

local setmetatable = setmetatable;

local get_config = require "core.configmanager".get;
local ldap       = module:require 'ldap';
local vcardlib   = module:require 'vcard';
local st         = require 'util.stanza';
local gettime    = require 'socket'.gettime;

local log = module._log

if not ldap then
    return;
end

local CACHE_EXPIRY = 300;

----------------------------------------
-- Utility Functions --
----------------------------------------

local function ldap_record_to_vcard(record, format)
    return vcardlib.create {
        record = record,
        format = format,
    }
end

local get_alias_for_user;

do
    local user_cache;
    local last_fetch_time;

    local function populate_user_cache()
        local user_c = get_config(module.host, 'ldap').user;
        if not user_c then return; end

        local ld = ldap.getconnection();

        local usernamefield = user_c.usernamefield;
        local namefield     = user_c.namefield;

        user_cache = {};

        for _, attrs in ld:search { base = user_c.basedn, scope = 'onelevel', filter = user_c.filter } do
            user_cache[attrs[usernamefield]] = attrs[namefield];
        end
        last_fetch_time = gettime();
    end

    function get_alias_for_user(user)
        if last_fetch_time and last_fetch_time + CACHE_EXPIRY < gettime() then
            user_cache = nil;
        end
        if not user_cache then
            populate_user_cache();
        end
        return user_cache[user];
    end
end

----------------------------------------
-- Base LDAP store class --
----------------------------------------

local function ldap_store(config)
    local self = {};
    local config = config;

    function self:get(username)
        return nil, "Data getting is not available for this storage backend";
    end

    function self:set(username, data)
        return nil, "Data setting is not available for this storage backend";
    end

    return self;
end

local adapters = {};

----------------------------------------
-- Roster Storage Implementation --
----------------------------------------

adapters.roster = function (config)
    -- Validate configuration requirements
    if not config.groups then return nil; end

    local self = ldap_store(config)

    function self:get(username)
        local ld = ldap.getconnection();
        local contacts = {};

        local memberfield = config.groups.memberfield;
        local namefield   = config.groups.namefield;
        local filter      = memberfield .. '=' .. tostring(username);

        local groups = {};
        for _, config in ipairs(config.groups) do
            groups[ config[namefield] ] = config.name;
        end

        log("debug", "Found %d group(s) for user %s", select('#', groups), username)

        -- XXX this kind of relies on the way we do groups at INOC
        for _, attrs in ld:search { base = config.groups.basedn, scope = 'onelevel', filter = filter } do
            if groups[ attrs[namefield] ] then
                local members = attrs[memberfield];

                for _, user in ipairs(members) do
                    if user ~= username then
                        local jid    = user .. '@' .. module.host;
                        local record = contacts[jid];

                        if not record then
                            record = {
                                subscription = 'both',
                                groups       = {},
                                name         = get_alias_for_user(user),
                            };
                            contacts[jid] = record;
                        end

                        record.groups[ groups[ attrs[namefield] ] ] = true;
                    end
                end
            end
        end

        return contacts;
    end

    function self:set(username, data)
        log("warn", "Setting data in Roster LDAP storage is not supported yet")
        return nil, "not supported";
    end

    return self;
end

----------------------------------------
-- vCard Storage Implementation --
----------------------------------------

adapters.vcard = function (config)
    -- Validate configuration requirements
    if not config.vcard_format or not config.user then return nil; end

    local self = ldap_store(config)

    function self:get(username)
        local ld     = ldap.getconnection();
        local filter = config.user.usernamefield .. '=' .. tostring(username);

        log("debug", "Retrieving vCard for user '%s'", username);

        local match = ldap.singlematch {
            base   = config.user.basedn,
            filter = filter,
        };
        if match then
            match.jid = username .. '@' .. module.host
            return st.preserialize(ldap_record_to_vcard(match, config.vcard_format));
        else
            return nil, "username not found";
        end
    end

    function self:set(username, data)
        log("warn", "Setting data in vCard LDAP storage is not supported yet")
        return nil, "not supported";
    end

    return self;
end

----------------------------------------
-- Driver Definition --
----------------------------------------

cache = {};

local driver = { name = "ldap" };

function driver:open(store)
    log("debug", "Opening ldap storage backend for host '%s' and store '%s'", module.host, store);

    if not cache[module.host] then
        log("debug", "Caching adapters for the host '%s'", module.host);

        local ad_config = get_config(module.host, "ldap");
        local ad_cache  = {};
        for k, v in pairs(adapters) do
            ad_cache[k] = v(ad_config);
        end

        cache[module.host] = ad_cache;
    end

    local adapter = cache[module.host][store];

    if not adapter then
        log("info", "Unavailable adapter for store '%s'", store);
        return nil, "unsupported-store";
    end
    return adapter;
end

function driver:stores(username, type, pattern)
    return nil, "not implemented";
end

function driver:store_exists(username, type)
    return nil, "not implemented";
end

function driver:purge(username)
    return nil, "not implemented";
end

function driver:nodes(type)
    return nil, "not implemented";
end

module:add_item("data-driver", driver);
