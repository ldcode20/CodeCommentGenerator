"""OS command injection (SEC002) — secure cases using the same APIs."""
import os
import shlex
import subprocess

from flask import request

ACTIONS = {"start", "stop", "restart"}


def argument_list_fixed_executable():
    host = request.args["host"]
    subprocess.run(["ping", "-c", "1", host])  # safe: SEC002


def explicit_no_shell():
    path = request.args["path"]
    subprocess.check_output(["ls", "-la", path], shell=False)  # safe: SEC002


def quoted_for_shell():
    host = request.args["host"]
    subprocess.run("ping -c 1 " + shlex.quote(host), shell=True)  # safe: SEC002


def allowlisted_action():
    action = request.args["action"]
    if action in ACTIONS:
        os.system("systemctl " + action + " app")  # safe: SEC002


def integer_argument():
    port = int(request.args["port"])
    os.system("nc -l %d" % port)  # safe: SEC002


def constant_shell_command():
    subprocess.run("ls -la /tmp | wc -l", shell=True)  # safe: SEC002


def run_command(cmd):
    return subprocess.check_output(cmd, shell=True)  # safe: SEC002


def only_constant_callers():
    run_command("uptime")
    run_command("df -h")
