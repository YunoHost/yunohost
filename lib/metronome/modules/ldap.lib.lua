-- vim:sts=4 sw=4

-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local ldap;
local connection;
local params  = module:get_option("ldap");
local format  = string.format;
local tconcat = table.concat;

local _M = {};

local config_params = {
    hostname = 'string',
    user     = {
        basedn        = 'string',
        namefield     = 'string',
        filter        = 'string',
        usernamefield = 'string',
    },
    groups   = {
        basedn      = 'string',
        namefield   = 'string',
        memberfield = 'string',

        _member = {
          name  = 'string',
          admin = 'boolean?',
        },
    },
    admin    = {
        _optional = true,
        basedn    = 'string',
        namefield = 'string',
        filter    = 'string',
    }
}

local function run_validation(params, config, prefix)
    prefix = prefix or '';

    -- verify that every required member of config is present in params
    for k, v in pairs(config) do
        if type(k) == 'string' and k:sub(1, 1) ~= '_' then
            local is_optional;
            if type(v) == 'table' then
                is_optional = v._optional;
            else
                is_optional = v:sub(-1) == '?';
            end

            if not is_optional and params[k] == nil then
                return nil, prefix .. k .. ' is required';
            end
        end
    end

    for k, v in pairs(params) do
        local expected_type = config[k];

        local ok, err = true;

        if type(k) == 'string' then
            -- verify that this key is present in config
            if k:sub(1, 1) == '_' or expected_type == nil then
                return nil, 'invalid parameter ' .. prefix .. k;
            end

            -- type validation
            if type(expected_type) == 'string' then
                if expected_type:sub(-1) == '?' then
                    expected_type = expected_type:sub(1, -2);
                end

                if type(v) ~= expected_type then
                    return nil, 'invalid type for parameter ' .. prefix .. k;
                end
            else -- it's a table (or had better be)
                if type(v) ~= 'table' then
                    return nil, 'invalid type for parameter ' .. prefix .. k;
                end

                -- recurse into child
                ok, err = run_validation(v, expected_type, prefix .. k .. '.');
            end
        else -- it's an integer (or had better be)
            if not config._member then
                return nil, 'invalid parameter ' .. prefix .. tostring(k);
            end
            ok, err = run_validation(v, config._member, prefix .. tostring(k) .. '.');
        end

        if not ok then
            return ok, err;
        end
    end

    return true;
end

local function validate_config()
    if true then
        return true; -- XXX for now
    end

    -- this is almost too clever (I mean that in a bad
    -- maintainability sort of way)
    --
    -- basically this allows a free pass for a key in group members
    -- equal to params.groups.namefield
    setmetatable(config_params.groups._member, {
        __index = function(_, k)
          if k == params.groups.namefield then
              return 'string';
          end
        end
    });

    local ok, err = run_validation(params, config_params);

    setmetatable(config_params.groups._member, nil);

    if ok then
        -- a little extra validation that doesn't fit into
        -- my recursive checker
        local group_namefield = params.groups.namefield;
        for i, group in ipairs(params.groups) do
            if not group[group_namefield] then
                return nil, format('groups.%d.%s is required', i, group_namefield);
            end
        end

        -- fill in params.admin if you can
        if not params.admin and params.groups then
          local admingroup;

          for _, groupconfig in ipairs(params.groups) do
              if groupconfig.admin then
                  admingroup = groupconfig;
                  break;
              end
          end

          if admingroup then
              params.admin = {
                  basedn    = params.groups.basedn,
                  namefield = params.groups.memberfield,
                  filter    = group_namefield .. '=' .. admingroup[group_namefield],
              };
          end
        end
    end

    return ok, err;
end

-- what to do if connection isn't available?
local function connect()
    return ldap.open_simple(params.hostname, params.bind_dn, params.bind_password, params.use_tls);
end

-- this is abstracted so we can maintain persistent connections at a later time
function _M.getconnection()
    return connect();
end

function _M.getparams()
  return params;
end

-- XXX consider renaming this...it doesn't bind the current connection
function _M.bind(username, password)
    local conn   = _M.getconnection();
    local filter = format('%s=%s', params.user.usernamefield, username);
    if params.user.usernamefield == 'mail' then
        filter = format('mail=%s@*', username);
    end    

    if filter then
        filter = _M.filter.combine_and(filter, params.user.filter);
    end

    local who = _M.singlematch {
        attrs     = params.user.usernamefield,
        base      = params.user.basedn,
        filter    = filter,
    };

    if who then
        who = who.dn;
        module:log('debug', '_M.bind - who: %s', who);
    else
        module:log('debug', '_M.bind - no DN found for username = %s', username);
        return nil, format('no DN found for username = %s', username);
    end

    local conn, err = ldap.open_simple(params.hostname, who, password, params.use_tls);

    if conn then
        conn:close();
        return true;
    end

    return conn, err;
end

function _M.singlematch(query)
    local ld = _M.getconnection();

    query.sizelimit = 1;
    query.scope     = 'subtree';

    for dn, attribs in ld:search(query) do
        attribs.dn = dn;
        return attribs;
    end
end

_M.filter = {};

function _M.filter.combine_and(...)
    local parts = { '(&' };

    local arg = { ... };

    for _, filter in ipairs(arg) do
        if filter:sub(1, 1) ~= '(' and filter:sub(-1) ~= ')' then
            filter = '(' .. filter .. ')'
        end
        parts[#parts + 1] = filter;
    end

    parts[#parts + 1] = ')';

    return tconcat(parts, '');
end

do
    local ok, err;

    metronome.unlock_globals();
    ok, ldap = pcall(require, 'lualdap');
    metronome.lock_globals();
    if not ok then
        module:log("error", "Failed to load the LuaLDAP library for accessing LDAP: %s", ldap);
        module:log("error", "More information on install LuaLDAP can be found at http://www.keplerproject.org/lualdap");
        return;
    end

    if not params then
        module:log("error", "LDAP configuration required to use the LDAP storage module");
        return;
    end

    ok, err = validate_config();

    if not ok then
        module:log("error", "LDAP configuration is invalid: %s", tostring(err));
        return;
    end
end

return _M;
