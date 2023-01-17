import os

from yunohost.interface.base import InterfaceKind, Field

if os.environ.get("INTERFACE") == "cli":
    from yunohost.interface.cli import Interface
elif os.environ.get("INTERFACE") == "api":
    from yunohost.interface.api import Interface
else:
    # FIXME for Moulinette to work
    from yunohost.interface.base import BaseInterface as Interface
