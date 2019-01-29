import json
import os
from moulinette import m18n
from moulinette.utils.log import getActionLogger
import settings
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

    currentTheme = settings.settings_get("ssowat.theme")
    logger.info(m18n.n('theme_current', theme=currentTheme))

def themes_set(auth, name):
    """
    Set currently active theme

    Keyword argument:
        name -- Theme name

    """
    from yunohost.app import app_ssowatconf

    ASKED_THEME_PATH = os.path.isdir(THEMES_PATH + name)

    # check that the asked theme exists in themes directory
    if ASKED_THEME_PATH:
        settings.settings_set('ssowat.theme', name)
        app_ssowatconf(auth)
        logger.success(m18n.n('theme_changed', theme=name))

    else:
        logger.error(m18n.n('theme_absent', theme=name))
