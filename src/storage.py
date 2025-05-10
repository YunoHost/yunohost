#
# Copyright (c) 2025 YunoHost Contributors
#
# This file is part of YunoHost (see https://yunohost.org)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
def storage_disk_list(**kargs):
    from yunohost.disk import disk_list

    return disk_list(**kargs)


def storage_disk_info(name, **kargs):
    from yunohost.disk import disk_info

    return disk_info(name, **kargs)


def storage_disk_health(name, **kargs):
    from yunohost.disk import disk_health

    return disk_health(name, **kargs)
