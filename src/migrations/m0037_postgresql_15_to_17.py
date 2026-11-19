#!/usr/bin/env python3
#
# Copyright (c) 2026 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
#

from .postgresql import PostgreSQLMigration


class MyMigration(PostgreSQLMigration):
    "Migrate DBs from Postgresql 15 to 17 after migrating to Trixie"

    previous_version = 15
    target_version = 17

    dependencies = ["migrate_to_trixie"]
