#!/usr/bin/env python3
#
# Copyright (c) 2024 YunoHost Contributors
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

import argparse
import datetime
import subprocess
from pathlib import Path

from jinja2 import Template

YUNOHOST_SRCDIR = Path(__file__).resolve().parent.parent

TREE = {
    "sources": {
        "title": "Sources",
        "notes": "This is coupled to the 'sources' resource in the manifest.toml",
        "subsections": ["sources"],
        "helpers": {},
    },
    "tech": {
        "title": "App technologies",
        "notes": "These allow to install specific version of the technology required to run some apps",
        "subsections": ["nodejs", "ruby", "go", "composer"],
        "helpers": {},
    },
    "db": {
        "title": "Databases",
        "notes": "This is coupled to the 'database' resource in the manifest.toml - at least for mysql/postgresql. Mongodb/redis may have better integration in the future.",
        "subsections": ["mysql", "postgresql", "mongodb", "redis"],
        "helpers": {},
    },
    "conf": {
        "title": "Configurations / templating",
        "subsections": [
            "templating",
            "nginx",
            "php",
            "systemd",
            "fail2ban",
            "logrotate",
        ],
        "helpers": {},
    },
    "misc": {
        "title": "Misc tools",
        "subsections": [
            "utils",
            "setting",
            "string",
            "backup",
            "logging",
            "multimedia",
        ],
        "helpers": {},
    },
    "meh": {
        "title": "Deprecated or handled by the core / app resources since v2",
        "subsections": ["permission", "apt", "systemuser"],
        "helpers": {},
    },
}


def get_current_commit() -> str:
    p = subprocess.Popen(
        "git rev-parse --verify HEAD",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, stderr = p.communicate()

    current_commit = stdout.strip().decode("utf-8")
    return current_commit


def render(tree, helpers_version: str) -> str:
    template_file = YUNOHOST_SRCDIR / "doc" / "helpers_doc_template.md.j2"
    template = Template(template_file.read_text())
    template.globals["now"] = datetime.datetime.utcnow

    changelog_file = YUNOHOST_SRCDIR / "debian" / "changelog"
    version = changelog_file.open("r").readline().split()[1].strip("()")

    result = template.render(
        tree=tree,
        date=datetime.datetime.now().strftime("%d/%m/%Y"),
        version=version,
        helpers_version=helpers_version,
        current_commit=get_current_commit(),
    )
    return result


##############################################################################


class Block:
    def __init__(self) -> None:
        self.name = ""
        self.line = -1
        self.comments: list[str] = []
        self.code: list[str] = []

        self.brief = ""
        self.details = ""
        self.usage = ""
        self.example = ""
        self.examples: list[str] = []
        self.args: list[list[str]] = []
        self.ret = ""


class Parser:
    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.file = filepath.open("r").readlines()
        self.blocks: list[Block] = []

    def parse_blocks(self) -> None:
        current_reading = "void"
        current_block = Block()

        for i, line in enumerate(self.file):
            if i == 0 and line.startswith("#!"):
                continue

            line = line.rstrip().replace("\t", "    ")

            if current_reading == "void":
                if is_global_comment(line):
                    # We start a new comment bloc
                    current_reading = "comments"
                    assert line.startswith("# ") or line == "#", malformed_error(i)
                    current_block.comments.append(line[2:])
                else:
                    pass
                    # assert line == "", malformed_error(i)
                continue

            elif current_reading == "comments":
                if is_global_comment(line):
                    # We're still in a comment bloc
                    assert line.startswith("# ") or line == "#", malformed_error(i)
                    current_block.comments.append(line[2:])
                elif line.strip() == "" or line.startswith("_ynh"):
                    # Well eh that was not an actual helper definition ... start over ?
                    current_reading = "void"
                    current_block = Block()
                elif not (line.endswith("{") or line.endswith("()")):
                    # Well we're not actually entering a function yet eh
                    # (c.f. global vars)
                    pass
                else:
                    # We're getting out of a comment bloc, we should find
                    # the name of the function
                    assert (
                        len(line.split()) >= 1
                    ), f"Malformed line {i} in {self.filepath}"
                    current_block.line = i
                    current_block.name = line.split()[0].strip("(){")
                    # Then we expect to read the function
                    current_reading = "code"

            elif current_reading == "code":
                if line == "}":
                    # We're getting out of the function
                    current_reading = "void"

                    # Then we keep this bloc and start a new one
                    # (we ignore helpers containing [internal] ...)
                    if (
                        "[packagingv1]" not in current_block.comments
                        and not any(
                            line.startswith("[internal]")
                            for line in current_block.comments
                        )
                        and not current_block.name.startswith("_")
                    ):
                        self.blocks.append(current_block)
                    current_block = Block()
                else:
                    current_block.code.append(line)

                continue

    def parse_block(self, b: Block) -> None:
        subblocks = "\n".join(b.comments).split("\n\n")

        for i, subblock in enumerate(subblocks):
            subblock = subblock.strip()

            if i == 0:
                b.brief = subblock
                continue

            elif subblock.startswith("example:"):
                b.example = " ".join(subblock.split()[1:])
                continue

            elif subblock.startswith("examples:"):
                b.examples = subblock.split("\n")[1:]
                continue

            elif subblock.startswith("usage"):
                for line in subblock.split("\n"):
                    if line.startswith("| arg"):
                        linesplit = line.split()
                        argname = linesplit[2]
                        # Detect that there's a long argument version (-f, --foo - Some description)
                        if argname.endswith(",") and linesplit[3].startswith("--"):
                            argname = argname.strip(",")
                            arglongname = linesplit[3]
                            argdescr = " ".join(linesplit[5:])
                            b.args.append([argname, arglongname, argdescr])
                        else:
                            argdescr = " ".join(linesplit[4:])
                            b.args.append([argname, argdescr])
                    elif line.startswith("| ret"):
                        b.ret = " ".join(line.split()[2:])
                    else:
                        if line.startswith("usage"):
                            line = " ".join(line.split()[1:])
                        b.usage += line + "\n"
                continue

            elif subblock.startswith("| arg"):
                for line in subblock.split("\n"):
                    if line.startswith("| arg"):
                        linesplit = line.split()
                        argname = linesplit[2]
                        # Detect that there's a long argument version (-f, --foo - Some description)
                        if argname.endswith(",") and linesplit[3].startswith("--"):
                            argname = argname.strip(",")
                            arglongname = linesplit[3]
                            argdescr = " ".join(linesplit[5:])
                            b.args.append([argname, arglongname, argdescr])
                        else:
                            argdescr = " ".join(linesplit[4:])
                            b.args.append([argname, argdescr])
                continue

            elif subblock:
                b.details += subblock + "\n\n"

        b.usage = b.usage.strip()


def is_global_comment(line: str) -> bool:
    return line.startswith("#")


def malformed_error(line_number: int) -> str:
    return f"Malformed file line {line_number} ?"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", type=str, choices=["1", "2", "2.1"])
    parser.add_argument("--output", "-o", type=Path, required=False)
    args = parser.parse_args()

    output = args.output if args.output else Path(f"helpers.v{args.version}.md")
    helpers_dir = YUNOHOST_SRCDIR / "helpers" / f"helpers.v{args.version}.d"

    for section in TREE.values():
        for subsection in section["subsections"]:
            print(f"Parsing {subsection} ...")
            helper_file = helpers_dir / subsection
            assert helper_file.is_file(), f"Uhoh, {helper_file} doesn't exists?"
            p = Parser(helper_file)
            p.parse_blocks()
            for b in p.blocks:
                p.parse_block(b)

            section["helpers"][subsection] = p.blocks  # type: ignore

    result = render(TREE, args.version)

    output.write_text(result)


if __name__ == "__main__":
    main()
