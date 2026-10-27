"""OS command injection (SEC002) — vulnerable cases."""
import html
import os
import subprocess
import sys
import subprocess as sp
from os import system as run_shell

from flask import request


def direct_system():
    host = input("host: ")
    os.system("ping -c 1 " + host)  # expect: SEC002


def shell_true_fstring():
    branch = request.args["branch"]
    subprocess.run(f"git checkout {branch}", shell=True)  # expect: SEC002


def module_alias():
    target = request.form["target"]
    sp.call("nslookup " + target, shell=True)  # expect: SEC002


def function_alias():
    path = request.args["path"]
    run_shell("ls -la " + path)  # expect: SEC002


def popen_string_without_shell():
    tool = request.args["tool"]
    subprocess.Popen(tool)  # expect: SEC002


def attacker_selects_executable():
    prog = request.args["prog"]
    subprocess.run([prog, "--version"])  # expect: SEC002


def wrong_sanitizer():
    name = html.escape(request.args["name"])
    os.system("echo " + name)  # expect: SEC002


def run_command(cmd):
    return subprocess.check_output(cmd, shell=True)  # expect: SEC002


def command_line_entry():
    run_command("grep -r " + sys.argv[1] + " .")


def environment_command():
    os.popen(os.environ["BACKUP_CMD"])  # expect: SEC002


def loop_built_command():
    cmd = "tar czf out.tgz"
    for f in request.args.getlist("file"):
        cmd = cmd + " " + f
    subprocess.call(cmd, shell=True)  # expect: SEC002


def two_sinks():
    user = request.args["user"]
    os.system("id " + user)  # expect: SEC002
    subprocess.getoutput("groups " + user)  # expect: SEC002


def nested_helper():
    host = request.args["host"]

    def go():
        os.system("traceroute " + host)  # expect: SEC002

    go()


def dynamic_lookup():
    cmd = request.args["cmd"]
    getattr(os, "system")(cmd)  # expect: SEC002


def apply_callback(fn, value):
    return fn(value)  # expect: SEC002 (known limitation)


def callback_caller():
    apply_callback(os.system, request.args["cmd"])


def computed_lookup():
    name = request.args["fn"]
    getattr(os, name)(request.args["arg"])  # expect: SEC002 (known limitation)
