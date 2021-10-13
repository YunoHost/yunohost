#!/usr/env/python3

import os
import glob
import datetime
import subprocess


def get_current_commit():
    p = subprocess.Popen(
        "git rev-parse --verify HEAD",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    stdout, stderr = p.communicate()

    current_commit = stdout.strip().decode("utf-8")
    return current_commit


def render(helpers):

    current_commit = get_current_commit()

    data = {
        "helpers": helpers,
        "date": datetime.datetime.now().strftime("%m/%d/%Y"),
        "version": open("../debian/changelog").readlines()[0].split()[1].strip("()"),
    }

    from jinja2 import Template
    from ansi2html import Ansi2HTMLConverter
    from ansi2html.style import get_styles

    conv = Ansi2HTMLConverter()
    shell_css = "\n".join(map(str, get_styles(conv.dark_bg)))

    def shell_to_html(shell):
        return conv.convert(shell, False)

    template = open("helper_doc_template.md", "r").read()
    t = Template(template)
    t.globals["now"] = datetime.datetime.utcnow
    result = t.render(
        current_commit=current_commit,
        data=data,
        convert=shell_to_html,
        shell_css=shell_css,
    )
    open("helpers.md", "w").write(result)


##############################################################################


class Parser:
    def __init__(self, filename):

        self.filename = filename
        self.file = open(filename, "r").readlines()
        self.blocks = None

    def parse_blocks(self):

        self.blocks = []

        current_reading = "void"
        current_block = {"name": None, "line": -1, "comments": [], "code": []}

        for i, line in enumerate(self.file):

            if line.startswith("#!/bin/bash"):
                continue

            line = line.rstrip().replace("\t", "    ")

            if current_reading == "void":
                if is_global_comment(line):
                    # We start a new comment bloc
                    current_reading = "comments"
                    assert line.startswith("# ") or line == "#", malformed_error(i)
                    current_block["comments"].append(line[2:])
                else:
                    pass
                    # assert line == "", malformed_error(i)
                continue

            elif current_reading == "comments":
                if is_global_comment(line):
                    # We're still in a comment bloc
                    assert line.startswith("# ") or line == "#", malformed_error(i)
                    current_block["comments"].append(line[2:])
                elif line.strip() == "":
                    # Well eh that was not an actual helper definition ... start over ?
                    current_reading = "void"
                    current_block = {
                        "name": None,
                        "line": -1,
                        "comments": [],
                        "code": [],
                    }
                elif not (line.endswith("{") or line.endswith("()")):
                    # Well we're not actually entering a function yet eh
                    # (c.f. global vars)
                    pass
                else:
                    # We're getting out of a comment bloc, we should find
                    # the name of the function
                    assert len(line.split()) >= 1, "Malformed line %s in %s" % (
                        i,
                        self.filename,
                    )
                    current_block["line"] = i
                    current_block["name"] = line.split()[0].strip("(){")
                    # Then we expect to read the function
                    current_reading = "code"

            elif current_reading == "code":

                if line == "}":
                    # We're getting out of the function
                    current_reading = "void"

                    # Then we keep this bloc and start a new one
                    # (we ignore helpers containing [internal] ...)
                    if "[internal]" not in current_block["comments"]:
                        self.blocks.append(current_block)
                    current_block = {
                        "name": None,
                        "line": -1,
                        "comments": [],
                        "code": [],
                    }
                else:
                    current_block["code"].append(line)

                continue

    def parse_block(self, b):

        b["brief"] = ""
        b["details"] = ""
        b["usage"] = ""
        b["args"] = []
        b["ret"] = ""

        subblocks = "\n".join(b["comments"]).split("\n\n")

        for i, subblock in enumerate(subblocks):
            subblock = subblock.strip()

            if i == 0:
                b["brief"] = subblock
                continue

            elif subblock.startswith("example:"):
                b["example"] = " ".join(subblock.split()[1:])
                continue

            elif subblock.startswith("examples:"):
                b["examples"] = subblock.split("\n")[1:]
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
                            b["args"].append((argname, arglongname, argdescr))
                        else:
                            argdescr = " ".join(linesplit[4:])
                            b["args"].append((argname, argdescr))
                    elif line.startswith("| ret"):
                        b["ret"] = " ".join(line.split()[2:])
                    else:
                        if line.startswith("usage"):
                            line = " ".join(line.split()[1:])
                        b["usage"] += line + "\n"
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
                            b["args"].append((argname, arglongname, argdescr))
                        else:
                            argdescr = " ".join(linesplit[4:])
                            b["args"].append((argname, argdescr))
                continue

            else:
                b["details"] += subblock + "\n\n"

        b["usage"] = b["usage"].strip()


def is_global_comment(line):
    return line.startswith("#")


def malformed_error(line_number):
    return "Malformed file line {} ?".format(line_number)


def main():

    helper_files = sorted(glob.glob("../data/helpers.d/*"))
    helpers = []

    for helper_file in helper_files:
        category_name = os.path.basename(helper_file)
        print("Parsing %s ..." % category_name)
        p = Parser(helper_file)
        p.parse_blocks()
        for b in p.blocks:
            p.parse_block(b)

        helpers.append((category_name, p.blocks))

    render(helpers)


main()
