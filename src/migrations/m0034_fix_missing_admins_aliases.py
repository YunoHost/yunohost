from ..domain import _get_maindomain
from ..tools import Migration
from ..user import _update_admins_group_aliases


class MyMigration(Migration):
    introduced_in_version = "12.1"
    dependencies = []

    def run(self, *args):
        _update_admins_group_aliases(
            old_main_domain=None, new_main_domain=_get_maindomain()
        )
