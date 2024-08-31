-- vim:sts=4 sw=4

-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2012 Rob Hoelz
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local st = require 'util.stanza';

local VCARD_NS = 'vcard-temp';

local builder_methods = {};

local base64_encode = require('util.encodings').base64.encode;

function builder_methods:addvalue(key, value)
    self.vcard:tag(key):text(value):up();
end

function builder_methods:addphotofield(tagname, format_section)
    local record = self.record;
    local format = self.format;
    local vcard  = self.vcard;
    local config = format[format_section];

    if not config then
        return;
    end

    if config.extval then
        if record[config.extval] then
            local tag = vcard:tag(tagname);
            tag:tag('EXTVAL'):text(record[config.extval]):up();
        end
    elseif config.type and config.binval then
        if record[config.binval] then
            local tag = vcard:tag(tagname);
            tag:tag('TYPE'):text(config.type):up();
            tag:tag('BINVAL'):text(base64_encode(record[config.binval])):up();
        end
    else
        module:log('error', 'You have an invalid %s config section', tagname);
        return;
    end

    vcard:up();
end

function builder_methods:addregularfield(tagname, format_section)
    local record = self.record;
    local format = self.format;
    local vcard  = self.vcard;

    if not format[format_section] then
        return;
    end

    local tag = vcard:tag(tagname);

    for k, v in pairs(format[format_section]) do
        tag:tag(string.upper(k)):text(record[v]):up();
    end

    vcard:up();
end

function builder_methods:addmultisectionedfield(tagname, format_section)
    local record = self.record;
    local format = self.format;
    local vcard  = self.vcard;

    if not format[format_section] then
        return;
    end

    for k, v in pairs(format[format_section]) do
        local tag = vcard:tag(tagname);

        if type(k) == 'string' then
            tag:tag(string.upper(k)):up();
        end

        for k2, v2 in pairs(v) do
            if type(v2) == 'boolean' then
                tag:tag(string.upper(k2)):up();
            else
                tag:tag(string.upper(k2)):text(record[v2]):up();
            end
        end

        vcard:up();
    end
end

function builder_methods:build()
    local record = self.record;
    local format = self.format;

    self:addvalue(              'VERSION',     '2.0');
    self:addvalue(              'FN',          record[format.displayname]);
    self:addregularfield(       'N',           'name');
    self:addvalue(              'NICKNAME',    record[format.nickname]);
    self:addphotofield(         'PHOTO',       'photo');
    self:addvalue(              'BDAY',        record[format.birthday]);
    self:addmultisectionedfield('ADR',         'address');
    self:addvalue(              'LABEL',       nil); -- we don't support LABEL...yet.
    self:addmultisectionedfield('TEL',         'telephone');
    self:addmultisectionedfield('EMAIL',       'email');
    self:addvalue(              'JABBERID',    record.jid);
    self:addvalue(              'MAILER',      record[format.mailer]);
    self:addvalue(              'TZ',          record[format.timezone]);
    self:addregularfield(       'GEO',         'geo');
    self:addvalue(              'TITLE',       record[format.title]);
    self:addvalue(              'ROLE',        record[format.role]);
    self:addphotofield(         'LOGO',        'logo');
    self:addvalue(              'AGENT',       nil); -- we don't support AGENT...yet.
    self:addregularfield(       'ORG',         'org');
    self:addvalue(              'CATEGORIES',  nil); -- we don't support CATEGORIES...yet.
    self:addvalue(              'NOTE',        record[format.note]);
    self:addvalue(              'PRODID',      nil); -- we don't support PRODID...yet.
    self:addvalue(              'REV',         record[format.rev]);
    self:addvalue(              'SORT-STRING', record[format.sortstring]);
    self:addregularfield(       'SOUND',       'sound');
    self:addvalue(              'UID',         record[format.uid]);
    self:addvalue(              'URL',         record[format.url]);
    self:addvalue(              'CLASS',       nil); -- we don't support CLASS...yet.
    self:addregularfield(       'KEY',         'key');
    self:addvalue(              'DESC',        record[format.description]);

    return self.vcard;
end

local function new_builder(params)
    local vcard_tag = st.stanza('vCard', { xmlns = VCARD_NS });

    local object = {
        vcard   = vcard_tag,
        __index = builder_methods,
    };

    for k, v in pairs(params) do
        object[k] = v;
    end

    setmetatable(object, object);

    return object;
end

local _M = {};

function _M.create(params)
    local builder = new_builder(params);

    return builder:build();
end

return _M;
