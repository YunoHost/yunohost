import os

if os.environ.get("INTERFACE", "cli") == "cli":
    from yunohost.interface.cli import Interface  # noqa
else:
    from yunohost.interface.api import Interface  # noqa
