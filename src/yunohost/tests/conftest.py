import sys
import moulinette

sys.path.append("..")


def pytest_addoption(parser):
    parser.addoption("--yunodebug", action="store_true", default=False)

###############################################################################
#   Tweak translator to raise exceptions if string keys are not defined       #
###############################################################################


old_translate = moulinette.core.Translator.translate
def new_translate(self, key, *args, **kwargs):

    if key not in self._translations[self.default_locale].keys():
        raise KeyError("Unable to retrieve key %s for default locale !" % key)

    return old_translate(self, key, *args, **kwargs)
moulinette.core.Translator.translate = new_translate

def new_m18nn(self, key, *args, **kwargs):
    return self._namespaces[self._current_namespace].translate(key, *args, **kwargs)

moulinette.core.Moulinette18n.n = new_m18nn

###############################################################################
#   Init the moulinette to have the cli loggers stuff                         #
###############################################################################


def pytest_cmdline_main(config):
    """Configure logging and initialize the moulinette"""
    # Define loggers handlers
    handlers = set(['tty'])
    root_handlers = set(handlers)

    # Define loggers level
    level = 'INFO'
    if config.option.yunodebug:
        tty_level = 'DEBUG'
    else:
        tty_level = 'SUCCESS'

    # Custom logging configuration
    logging = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
            'tty-debug': {
                'format': '%(relativeCreated)-4d %(fmessage)s'
            },
            'precise': {
                'format': '%(asctime)-15s %(levelname)-8s %(name)s %(funcName)s - %(fmessage)s'
            },
        },
        'filters': {
            'action': {
                '()': 'moulinette.utils.log.ActionFilter',
            },
        },
        'handlers': {
            'tty': {
                'level': tty_level,
                'class': 'moulinette.interfaces.cli.TTYHandler',
                'formatter': '',
            },
        },
        'loggers': {
            'yunohost': {
                'level': level,
                'handlers': handlers,
                'propagate': False,
            },
            'moulinette': {
                'level': level,
                'handlers': [],
                'propagate': True,
            },
            'moulinette.interface': {
                'level': level,
                'handlers': handlers,
                'propagate': False,
            },
        },
        'root': {
            'level': level,
            'handlers': root_handlers,
        },
    }

    # Initialize moulinette
    moulinette.init(logging_config=logging, _from_source=False)
    moulinette.m18n.load_namespace('yunohost')
