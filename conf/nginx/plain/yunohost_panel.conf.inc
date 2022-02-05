# Insert YunoHost button + portal overlay
sub_filter </head> '<script type="text/javascript" src="/ynh_portal.js"></script><link type="text/css" rel="stylesheet" href="/ynh_overlay.css"><script type="text/javascript" src="/ynhtheme/custom_portal.js"></script><link type="text/css" rel="stylesheet" href="/ynhtheme/custom_overlay.css"></head>';
sub_filter_once on;
# Apply to other mime types than text/html
sub_filter_types application/xhtml+xml;
# Prevent YunoHost panel files from being blocked by specific app rules
location ~ (ynh_portal.js|ynh_overlay.css|ynh_userinfo.json|ynhtheme/custom_portal.js|ynhtheme/custom_overlay.css) {
}
