-- ** Metronome's config file example **
-- 
-- The format is exactly equal to Prosody's:
--
-- Lists are written { "like", "this", "one" } 
-- Lists can also be of { 1, 2, 3 } numbers, etc. 
-- Either commas, or semi-colons; may be used as seperators.
--
-- A table is a list of values, except each value has a name. An 
-- example would be:
--
-- ssl = { key = "keyfile.key", certificate = "certificate.crt" }
--
-- Tip: You can check that the syntax of this file is correct when you have finished
-- by running: luac -p metronome.cfg.lua
-- If there are any errors, it will let you know what and where they are, otherwise it 
-- will keep quiet.

-- Global settings go in this section
 
-- This is the list of modules Metronome will load on startup.
-- It looks for mod_modulename.lua in the plugins folder, so make sure that exists too.

pidfile = "/var/run/metronome/metronome.pid"

log = {
        info = "/var/log/metronome/metronome.log"; -- Change 'info' to 'debug' for verbose logging
        error = "/var/log/metronome/metronome.err";
        "*syslog";
}

modules_enabled = {

        -- Generally required
                "roster"; -- Allow users to have a roster. Recommended ;)
                "saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
                "tls"; -- Add support for secure TLS on c2s/s2s connections
                "dialback"; -- s2s dialback support
                "disco"; -- Service discovery

        -- Not essential, but recommended
                "private"; -- Private XML storage (for room bookmarks, etc.)
                "vcard"; -- Allow users to set vCards
                "privacy"; -- Support privacy lists
                --"compression"; -- Stream compression (Debian: requires lua-zlib module to work)

        -- Nice to have
                "legacyauth"; -- Legacy authentication. Only used by some old clients and bots.
                "version"; -- Replies to server version requests
                "uptime"; -- Report how long server has been running
                "time"; -- Let others know the time here on this server
                "ping"; -- Replies to XMPP pings with pongs
                "pep"; -- Enables users to publish their mood, activity, playing music and more
                "register"; -- Allow users to register on this server using a client and change passwords
                "adhoc"; -- Support for "ad-hoc commands" that can be executed with an XMPP client

        -- Admin interfaces
                "admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
                "admin_telnet"; -- Opens telnet console interface on localhost port 5582

        -- Other specific functionality
                "bosh"; -- Enable BOSH clients, aka "Jabber over HTTP"
                --"httpserver"; -- Serve static files from a directory over HTTP
                --"groups"; -- Shared roster support
                --"announce"; -- Send announcement to all online users
                --"welcome"; -- Welcome users who register accounts
                --"watchregistrations"; -- Alert admins of registrations
                --"motd"; -- Send a message to users when they log in
                "mam"; -- Nice archive management
        -- Debian: do not remove this module, or you lose syslog
        -- support
                "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
};

-- Discovery items
disco_items = {
        { "muc.yunohost.org" },
        { "vjud.yunohost.org" },
        { "pubsub.yunohost.org" }
};

use_ipv6 = true
c2s_require_encryption = false
s2s_secure = true

-- HTTP ports
http_ports = { 5290 }
https_ports = { 5291 }

-- BOSH configuration (mod_bosh)
bosh_max_inactivity = 30
consider_bosh_secure = true
cross_domain_bosh = true

anonymous_login = false
allow_registration = false

storage = "ldap"

Component "localhost" "http"
        modules_enabled = { "bosh" }

Component "muc.yunohost.org" "muc"
        name = "YunoHost Chatrooms"

        modules_enabled = {
                "muc_limits";
                "muc_log";
                "muc_log_http";
        }

        muc_event_rate = 0.5
        muc_burst_factor = 10

        muc_log_http = {
                http_port = 5290;
                show_join = true;
                show_status = false;
                theme = "metronome";
        }

Component "pubsub.yunohost.org" "pubsub"
        name = "YunoHost Publish/Subscribe"
        unrestricted_node_creation = true

Component "vjud.yunohost.org" "vjud"
        ud_disco_name = "Jappix User Directory"

Include "conf.d/*.cfg.lua"


