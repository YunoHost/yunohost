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
-- ssl = { key = "keyfile.key", certificate = "certificate.cert" }
--
-- Tip: You can check that the syntax of this file is correct when you have finished
-- by running: luac -p metronome.cfg.lua
-- If there are any errors, it will let you know what and where they are, otherwise it
-- will keep quiet.

-- Global settings go in this section

-- This is the list of modules Metronome will load on startup.
-- It looks for mod_modulename.lua in the plugins folder, so make sure that exists too.

modules_enabled = {
    -- Generally required
        "roster"; -- Allow users to have a roster. Recommended.
        "saslauth"; -- Authentication for clients. Recommended if you want to log in.
        "tls"; -- Add support for secure TLS on c2s/s2s connections
        "disco"; -- Service discovery

    -- Not essential, but recommended
        "private"; -- Private XML storage (for room bookmarks, etc.)
        "vcard"; -- Allow users to set vCards
        "pep"; -- Allows setting of mood, tune, etc.
        "pubsub";  -- Publish-subscribe XEP-0060
        "posix"; -- POSIX functionality, sends server to background, enables syslog, etc.
        "bidi"; -- Enables Bidirectional Server-to-Server Streams.

    -- Nice to have
        "version"; -- Replies to server version requests
        "uptime"; -- Report how long server has been running
        "time"; -- Let others know the time here on this server
        "ping"; -- Replies to XMPP pings with pongs
        "register"; -- Allow users to register on this server using a client and change passwords
        "stream_management"; -- Allows clients and servers to use Stream Management
        "stanza_optimizations"; -- Allows clients to use Client State Indication and SIFT
        "message_carbons"; -- Allows clients to enable carbon copies of messages
        "mam"; -- Enable server-side message archives using Message Archive Management
        "push"; -- Enable Push Notifications via PubSub using XEP-0357
        "lastactivity"; -- Enables clients to know the last presence status of an user
        "adhoc_cm"; -- Allow to set client certificates to login through SASL External via adhoc
        "admin_adhoc"; -- administration adhoc commands
        "bookmarks"; -- XEP-0048 Bookmarks synchronization between PEP and Private Storage
        "sec_labels"; -- Allows to use a simplified version XEP-0258 Security Labels and related ACDFs.
        "privacy"; -- Add privacy lists and simple blocking command support

        -- Other specific functionality
        --"admin_telnet"; -- administration console, telnet to port 5582
        --"admin_web"; -- administration web interface
        "bosh"; -- Enable support for BOSH clients, aka "XMPP over Bidirectional Streams over Synchronous HTTP"
        --"compression"; -- Allow clients to enable Stream Compression
        --"spim_block"; -- Require authorization via OOB form for messages from non-contacts and block unsollicited messages
        --"gate_guard"; -- Enable config-based blacklisting and hit-based auto-banning features
        --"incidents_handling"; -- Enable Incidents Handling support (can be administered via adhoc commands)
        --"server_presence"; -- Enables Server Buddies extension support
        --"service_directory"; -- Enables Service Directories extension support
        --"public_service"; -- Enables Server vCard support for public services in directories and advertises in features
        --"register_api"; -- Provides secure API for both Out-Of-Band and In-Band registration for E-Mail verification
        "websocket"; -- Enable support for WebSocket clients, aka "XMPP over WebSockets"
};

-- Server PID
pidfile = "/var/run/metronome/metronome.pid"

-- HTTP server
http_ports = { 5290 }
http_interfaces = { "127.0.0.1", "::1" }

--https_ports = { 5291 }
--https_interfaces = { "127.0.0.1", "::1" }

-- Enable IPv6
use_ipv6 = true

-- BOSH configuration (mod_bosh)
consider_bosh_secure = true
cross_domain_bosh = true

-- WebSocket configuration (mod_websocket)
consider_websocket_secure = true
cross_domain_websocket = true

-- Disable account creation by default, for security
allow_registration = false

-- Use LDAP storage backend for all stores
storage = "ldap"

-- stanza optimization
csi_config_queue_all_muc_messages_but_mentions = false;


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

----------- Virtual hosts -----------
-- You need to add a VirtualHost entry for each domain you wish Metronome to serve.
-- Settings under each VirtualHost entry apply *only* to that host.

Include "conf.d/*.cfg.lua"
