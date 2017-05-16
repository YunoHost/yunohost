# Insert YunoHost panel
sub_filter </head> '<script type="text/javascript" src="/ynhpanel.js"></script></head>';
sub_filter_once on;
# Apply to other mime types than text/html
sub_filter_types application/xhtml+xml;
# Prevent YunoHost panel files from being blocked by specific app rules
location ~ ynhpanel\.(js|json|css) {
}
