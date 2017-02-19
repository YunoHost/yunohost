import sys
import moulinette

sys.path.append("..")

old_init = moulinette.core.Moulinette18n.__init__


def monkey_path_i18n_init(self, package, default_locale="en"):
    old_init(self, package, default_locale)
    self.load_namespace("yunohost")


moulinette.core.Moulinette18n.__init__ = monkey_path_i18n_init

moulinette.init()
