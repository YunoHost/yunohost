-- mod_auth_ldap

local jid_split = require "util.jid".split;
local new_sasl = require "util.sasl".new;
local lualdap = require "lualdap";

local function ldap_filter_escape(s)
	return (s:gsub("[*()\\%z]", function(c) return ("\\%02x"):format(c:byte()) end));
end

-- Config options
local ldap_server = module:get_option_string("ldap_server", "localhost");
local ldap_rootdn = module:get_option_string("ldap_rootdn", "");
local ldap_password = module:get_option_string("ldap_password", "");
local ldap_tls = module:get_option_boolean("ldap_tls");
local ldap_scope = module:get_option_string("ldap_scope", "subtree");
local ldap_filter = module:get_option_string("ldap_filter", "(uid=$user)"):gsub("%%s", "$user", 1);
local ldap_base = assert(module:get_option_string("ldap_base"), "ldap_base is a required option for ldap");
local ldap_mode = module:get_option_string("ldap_mode", "bind");
local ldap_admins = module:get_option_string("ldap_admin_filter");
local host = ldap_filter_escape(module:get_option_string("realm", module.host));

-- Initiate connection
local ld = nil;
module.unload = function() if ld then pcall(ld, ld.close); end end

function ldap_do_once(method, ...)
	if ld == nil then
		local err;
		ld, err = lualdap.open_simple(ldap_server, ldap_rootdn, ldap_password, ldap_tls);
		if not ld then return nil, err, "reconnect"; end
	end

	-- luacheck: ignore 411/success
	local success, iterator, invariant, initial = pcall(ld[method], ld, ...);
	if not success then ld = nil; return nil, iterator, "search"; end

	local success, dn, attr = pcall(iterator, invariant, initial);
	if not success then ld = nil; return success, dn, "iter"; end

	return dn, attr, "return";
end

function ldap_do(method, retry_count, ...)
	local dn, attr, where;
	for _=1,1+retry_count do
		dn, attr, where = ldap_do_once(method, ...);
		if dn or not(attr) then break; end -- nothing or something found
		module:log("warn", "LDAP: %s %s (in %s)", tostring(dn), tostring(attr), where);
		-- otherwise retry
	end
	if not dn and attr then
		module:log("error", "LDAP: %s", tostring(attr));
	end
	return dn, attr;
end

local function get_user(username)
	module:log("debug", "get_user(%q)", username);
	return ldap_do("search", 2, {
		base = ldap_base;
		scope = ldap_scope;
		sizelimit = 1;
		filter = ldap_filter:gsub("%$(%a+)", {
			user = ldap_filter_escape(username);
			host = host;
		});
	});
end

local provider = {};

function provider.create_user(username, password) -- luacheck: ignore 212
	return nil, "Account creation not available with LDAP.";
end

function provider.user_exists(username)
	return not not get_user(username);
end

function provider.set_password(username, password)
	local dn, attr = get_user(username);
	if not dn then return nil, attr end
	if attr.userPassword == password then return true end
	return ldap_do("modify", 2, dn, { '=', userPassword = password });
end

if ldap_mode == "getpasswd" then
	function provider.get_password(username)
		local dn, attr = get_user(username);
		if dn and attr then
			return attr.userPassword;
		end
	end

	function provider.test_password(username, password)
		return provider.get_password(username) == password;
	end

	function provider.get_sasl_handler()
		return new_sasl(module.host, {
			plain = function(sasl, username) -- luacheck: ignore 212/sasl
				local password = provider.get_password(username);
				if not password then return "", nil; end
				return password, true;
			end
		});
	end
elseif ldap_mode == "bind" then
	local function test_password(userdn, password)
		return not not lualdap.open_simple(ldap_server, userdn, password, ldap_tls);
	end

	function provider.test_password(username, password)
		local dn = get_user(username);
		if not dn then return end
		return test_password(dn, password)
	end

	function provider.get_sasl_handler()
		return new_sasl(module.host, {
			plain_test = function(sasl, username, password) -- luacheck: ignore 212/sasl
				return provider.test_password(username, password), true;
			end
		});
	end
else
	module:log("error", "Unsupported ldap_mode %s", tostring(ldap_mode));
end

if ldap_admins then
	function provider.is_admin(jid)
		local username = jid_split(jid);
		return ldap_do("search", 2, {
			base = ldap_base;
			scope = ldap_scope;
			sizelimit = 1;
			filter = ldap_admins:gsub("%$(%a+)", {
				user = ldap_filter_escape(username);
				host = host;
			});
		});
	end
end

module:provides("auth", provider);
