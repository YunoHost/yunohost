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

---------- Server-wide settings ----------
-- Settings in this section apply to the whole server and are the default settings
-- for any virtual hosts

-- Server PID
pidfile = "/var/run/metronome/metronome.pid"

-- HTTP server
http_ports = { 5290 }
http_interfaces = { "127.0.0.1", "::1" }

--https_ports = { 5291 }
--https_interfaces = { "127.0.0.1", "::1" }

-- Enable IPv6
use_ipv6 = true

-- This is the list of modules Metronome will load on startup.
-- It looks for mod_modulename.lua in the plugins folder, so make sure that exists too.
modules_enabled = {

    -- Generally required
        "roster"; -- Allow users to have a roster. Recommended ;)
        "saslauth"; -- Authentication for clients and servers. Recommended if you want to log in.
        "tls"; -- Add support for secure TLS on c2s/s2s connections
        "dialback"; -- s2s dialback support
        "disco"; -- Service discovery
        --"discoitems"; -- Service discovery items
        --"extdisco"; -- External Service Discovery

    -- Not essential, but recommended
        "private"; -- Private XML storage (for room bookmarks, etc.)
        "vcard"; -- Allow users to set vCards
        "privacy"; -- Support privacy lists

    -- These are commented by default as they have a performance impact
        --"compression"; -- Stream compression (Debian: requires lua-zlib module to work)

    -- Nice to have
        "version"; -- Replies to server version requests
        "uptime"; -- Report how long server has been running
        "time"; -- Let others know the time here on this server
        "ping"; -- Replies to XMPP pings with pongs
        "pep"; -- Enables users to publish their mood, activity, playing music and more
        "message_carbons"; -- Allow clients to keep in sync with messages send on other resources
        "register"; -- Allow users to register on this server using a client and change passwords
        "adhoc"; -- Support for "ad-hoc commands" that can be executed with an XMPP client

    -- Admin interfaces
        "admin_adhoc"; -- Allows administration via an XMPP client that supports ad-hoc commands
        "admin_telnet"; -- Opens telnet console interface on localhost port 5582

    -- HTTP modules
        "bosh"; -- Enable BOSH clients, aka "Jabber over HTTP"
        --"websockets"; -- Enable WebSocket clients
        --"http_files"; -- Serve static files from a directory over HTTP

    -- Other specific functionality
--        "bidi"; -- Bidirectional Streams for S2S connections
--        "stream_management"; -- Stream Management support
        --"groups"; -- Shared roster support
        --"announce"; -- Send announcement to all online users
        --"welcome"; -- Welcome users who register accounts
        --"watchregistrations"; -- Alert admins of registrations
        --"motd"; -- Send a message to users when they log in
        "mam"; -- Nice archive management
        --"legacyauth"; -- Legacy authentication. Only used by some old clients and bots.
        "offline"; -- Store offline messages
        "c2s"; -- Handle client connections
        "s2s"; -- Handle server-to-server connections

    -- Debian: do not remove this module, or you lose syslog
    -- support
        "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
};

-- Discovery items
disco_items = {
    { "muc.{{ main_domain }}" },
    { "pubsub.{{ main_domain }}" },
    { "vjud.{{ main_domain }}" }
};

-- BOSH configuration (mod_bosh)
bosh_max_inactivity = 30
consider_bosh_secure = true
cross_domain_bosh = true

-- Disable account creation by default, for security
allow_registration = false

-- SSL/TLS configuration
ssl = {
    options = {
        "no_sslv2",
        "no_sslv3",
        "no_ticket",
        "no_compression",
        "cipher_server_preference"
    };
}

-- Force clients to use encrypted connections? This option will
-- prevent clients from authenticating unless they are using encryption.
c2s_require_encryption = true

-- Force servers to use encrypted connections? This option will
-- prevent servers from connecting unless they are using encryption.
s2s_require_encryption = true

-- Allow servers to use an unauthenticated encryption channel
s2s_allow_encryption = true

allow_unencrypted_plain_auth = false;

s2s_secure = true
s2s_secure_auth = false

--anonymous_login = false

-- Use LDAP storage backend for all stores
storage = "ldap"

-- Logging configuration
log = {
    info = "/var/log/metronome/metronome.log"; -- Change 'info' to 'debug' for verbose logging
    error = "/var/log/metronome/metronome.err";
    -- "*syslog"; -- Uncomment this for logging to syslog
    -- "*console"; -- Log to the console, useful for debugging with daemonize=false
}


------ Components ------
-- You can specify components to add hosts that provide special services,
-- like multi-user conferences, and transports.

---Set up a local BOSH service
Component "localhost" "http"
    modules_enabled = { "bosh" }

---Set up a MUC (multi-user chat) room server
Component "muc.{{ main_domain }}" "muc"
    name = "YunoHost Chatrooms"

    modules_enabled = {
        "muc_limits";
        "muc_log";
        "muc_log_http";
    }

    muc_event_rate = 0.5
    muc_burst_factor = 10

    muc_log_http_config = {
        url_base = "logs";
        theme = "metronome";
    }

---Set up a PubSub server
Component "pubsub.{{ main_domain }}" "pubsub"
    name = "YunoHost Publish/Subscribe"

    unrestricted_node_creation = true -- Anyone can create a PubSub node (from any server)

---Set up a VJUD service
Component "vjud.{{ main_domain }}" "vjud"
    ud_disco_name = "Jappix User Directory"


----------- Virtual hosts -----------
-- You need to add a VirtualHost entry for each domain you wish Metronome to serve.
-- Settings under each VirtualHost entry apply *only* to that host.

Include "conf.d/*.cfg.lua"

