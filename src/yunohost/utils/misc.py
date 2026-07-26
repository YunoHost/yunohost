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
import binascii
import os
import textwrap


def random_ascii(length: int = 40) -> str:
    """Return a random ascii string"""
    return binascii.hexlify(os.urandom(length)).decode("ascii")[:length]


def send_admin_email(from_addr: str, subject: str, content: str) -> None:
    to_addr = "root"
    message = (
        textwrap.dedent(f"""\
            From: {from_addr}
            To: {to_addr}
            Subject: {subject}

        """)
        + content
    )

    import smtplib

    smtp = smtplib.SMTP("localhost")
    smtp.sendmail(from_addr, [to_addr], message.encode("utf-8"))
    smtp.quit()
