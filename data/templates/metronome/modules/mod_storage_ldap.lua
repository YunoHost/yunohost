-- vim:sts=4 sw=4

-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

----------------------------------------
-- Constants and such --
----------------------------------------

local setmetatable = setmetatable;
local ldap         = module:require 'ldap';
local vcardlib     = module:require 'vcard';
local st           = require 'util.stanza';
local gettime      = require 'socket'.gettime;

if not ldap then
    return;
end

local CACHE_EXPIRY = 300;
local params       = module:get_option('ldap');

----------------------------------------
-- Utility Functions --
----------------------------------------

local function ldap_record_to_vcard(record)
    return vcardlib.create {
        record = record,
        format = params.vcard_format,
    }
end

local get_alias_for_user;

do
  local user_cache;
  local last_fetch_time;

  local function populate_user_cache()
      local ld = ldap.getconnection();

      local usernamefield = params.user.usernamefield;
      local namefield     = params.user.namefield;

      user_cache = {};

      for _, attrs in ld:search { base = params.user.basedn, scope = 'onelevel', filter = params.user.filter } do
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
-- General Setup --
----------------------------------------

local ldap_store   = {};
ldap_store.__index = ldap_store;

local adapters = {
    roster = {},
    vcard  = {},
}

for k, v in pairs(adapters) do
    setmetatable(v, ldap_store);
    v.__index = v;
    v.name    = k;
end

function ldap_store:get(username)
    return nil, "get method unimplemented on store '" .. tostring(self.name) .. "'"
end

function ldap_store:set(username, data)
    return nil, "LDAP storage is currently read-only";
end

----------------------------------------
-- Roster Storage Implementation --
----------------------------------------

function adapters.roster:get(username)
    local ld = ldap.getconnection();
    local contacts = {};

    local memberfield = params.groups.memberfield;
    local namefield   = params.groups.namefield;
    local filter      = memberfield .. '=' .. tostring(username);

    local groups = {};
    for _, config in ipairs(params.groups) do
        groups[ config[namefield] ] = config.name;
    end

    -- XXX this kind of relies on the way we do groups at INOC
    for _, attrs in ld:search { base = params.groups.basedn, scope = 'onelevel', filter = filter } do
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

----------------------------------------
-- vCard Storage Implementation --
----------------------------------------

function adapters.vcard:get(username)
    if not params.vcard_format then
        return nil, '';
    end

    local ld     = ldap.getconnection();
    local filter = params.user.usernamefield .. '=' .. tostring(username);

    local match = ldap.singlematch {
        base   = params.user.basedn,
        filter = filter,
    };
    if match then
        match.jid = username .. '@' .. module.host
        return st.preserialize(ldap_record_to_vcard(match));
    else
        return nil, 'not found';
    end
end

----------------------------------------
-- Driver Definition --
----------------------------------------

local driver = {};

function driver:open(store, typ)
    local adapter = adapters[store];

    if adapter and not typ then
        return adapter;
    end
    return nil, "unsupported-store";
end
module:provides("storage", driver);
