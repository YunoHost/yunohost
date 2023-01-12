import os

from yunohost.interface.base import InterfaceKind

if os.environ.get("INTERFACE", "cli") == "cli":
    from yunohost.interface.cli import Interface
else:
    from yunohost.interface.api import Interface

