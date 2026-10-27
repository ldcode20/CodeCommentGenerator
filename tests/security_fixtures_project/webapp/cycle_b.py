import subprocess

from webapp import cycle_a


def pong(n, cmd):
    if n % 2 == 0:
        subprocess.run(cmd, shell=True)  # expect: SEC002
    return cycle_a.ping(n - 1, cmd)
