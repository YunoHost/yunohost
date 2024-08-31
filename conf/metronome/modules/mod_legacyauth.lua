-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--



local st = require "util.stanza";
local t_concat = table.concat;

local secure_auth_only = module:get_option("c2s_require_encryption")
    or module:get_option("require_encryption")
    or not(module:get_option("allow_unencrypted_plain_auth"));

local sessionmanager = require "core.sessionmanager";
local usermanager = require "core.usermanager";
local nodeprep = require "util.encodings".stringprep.nodeprep;
local resourceprep = require "util.encodings".stringprep.resourceprep;

module:add_feature("jabber:iq:auth");
module:hook("stream-features", function(event)
    local origin, features = event.origin, event.features;
    if secure_auth_only and not origin.secure then
        -- Sorry, not offering to insecure streams!
        return;
    elseif not origin.username then
        features:tag("auth", {xmlns='http://jabber.org/features/iq-auth'}):up();
    end
end);

module:hook("stanza/iq/jabber:iq:auth:query", function(event)
    local session, stanza = event.origin, event.stanza;

    if session.type ~= "c2s_unauthed" then
        (session.sends2s or session.send)(st.error_reply(stanza, "cancel", "service-unavailable", "Legacy authentication is only allowed for unauthenticated client connections."));
        return true;
    end

    if secure_auth_only and not session.secure then
        session.send(st.error_reply(stanza, "modify", "not-acceptable", "Encryption (SSL or TLS) is required to connect to this server"));
        return true;
    end

    local username = stanza.tags[1]:child_with_name("username");
    local password = stanza.tags[1]:child_with_name("password");
    local resource = stanza.tags[1]:child_with_name("resource");
    if not (username and password and resource) then
        local reply = st.reply(stanza);
        session.send(reply:query("jabber:iq:auth")
            :tag("username"):up()
            :tag("password"):up()
            :tag("resource"):up());
    else
        username, password, resource = t_concat(username), t_concat(password), t_concat(resource);
        username = nodeprep(username);
        resource = resourceprep(resource)
        if not (username and resource) then
            session.send(st.error_reply(stanza, "modify", "bad-request"));
            return true;
        end
        if usermanager.test_password(username, session.host, password) then
            -- Authentication successful!
            local success, err = sessionmanager.make_authenticated(session, username);
            if success then
                local err_type, err_msg;
                success, err_type, err, err_msg = sessionmanager.bind_resource(session, resource);
                if not success then
                    session.send(st.error_reply(stanza, err_type, err, err_msg));
                    session.username, session.type = nil, "c2s_unauthed"; -- FIXME should this be placed in sessionmanager?
                    return true;
                elseif resource ~= session.resource then -- server changed resource, not supported by legacy auth
                    session.send(st.error_reply(stanza, "cancel", "conflict", "The requested resource could not be assigned to this session."));
                    session:close(); -- FIXME undo resource bind and auth instead of closing the session?
                    return true;
                end
            end
            session.send(st.reply(stanza));
        else
            session.send(st.error_reply(stanza, "auth", "not-authorized"));
        end
    end
    return true;
end);
