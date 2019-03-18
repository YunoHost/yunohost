# Insert YunoHost panel
sub_filter </head> '<script type="text/javascript" src="/ynhpanel.js"></script><link type="text/css" rel="stylesheet" href="/ynhpanel.css"></link><script type="text/javascript" src="/ynhtheme/custom.js"></script><link type="text/css" rel="stylesheet" href="/ynhtheme/custom.css"></link></head>';
sub_filter_once on;
# Apply to other mime types than text/html
sub_filter_types application/xhtml+xml;
# Prevent YunoHost panel files from being blocked by specific app rules
location ~ ynhpanel\.(js|json|css) {
}
