import json
import os
from moulinette import m18n
from moulinette.utils.log import getActionLogger
logger = getActionLogger('yunohost.themes')

THEMES_PATH = '/usr/share/ssowat/portal/assets/themes/'


def themes_list():
    """
    List all installed themes

    """

    themesList = [f for f in os.listdir(THEMES_PATH) if os.path.isdir(os.path.join(THEMES_PATH, f))]

    return { 'themes': themesList }

def themes_get():
    """
    Get currently active theme

    """

    with open('/etc/ssowat/conf.json') as f:
        ssowatConf = json.loads(str(f.read()))

    logger.info(m18n.n('theme_current', theme=ssowatConf["theme"]))

def themes_set(name):
    """
    Set currently active theme

    Keyword argument:
        name -- Theme name

    """

    SSOWAT_CONFIG_LOCATION = '/etc/ssowat/conf.json'
    ASKED_THEME_PATH = os.path.isdir(THEMES_PATH + name)

    if ASKED_THEME_PATH:

        with open(SSOWAT_CONFIG_LOCATION, 'r') as f:
            data = json.load(f)
            data['theme'] = name

        os.remove(SSOWAT_CONFIG_LOCATION)
        with open(SSOWAT_CONFIG_LOCATION, 'w') as f:
            json.dump(data, f, indent=4)

        logger.success(m18n.n('theme_changed', theme=name))

    else:

        logger.error(m18n.n('theme_absent', theme=name))
