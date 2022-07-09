import json
import logging
import os
import shlex
import subprocess
from configparser import ConfigParser
from pathlib import Path

from yawsso import TRACE

logger = logging.getLogger(__name__)


def xu(path):
    if str(path).startswith('~'):
        return os.path.expanduser(path)
    else:
        return path


def halt(error):
    logger.error(error)
    exit(1)


def invoke(cmd):
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT).decode()
        success = True
    except subprocess.CalledProcessError as e:
        output = e.output.decode()
        success = False
    return success, output.strip('\n')


def poll(cmd, output=True):
    proc = subprocess.Popen(
        shlex.split(cmd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    success = True

    while True:
        line = proc.stdout.readline()
        if not line:
            break
        line = line.rstrip('\n')  # pragma: no cover
        if line != "" and output:  # pragma: no cover
            logger.info(line)  # pragma: no cover

    for line in proc.stderr.readlines():
        line = line.rstrip('\n')
        if line != "":
            logger.error(line)
            success = False

    return success


def list_directory(path):
    file_paths = []
    if os.path.exists(path):
        file_paths = Path(path).iterdir()
    file_paths = sorted(file_paths, key=os.path.getmtime)
    file_paths.reverse()  # sort by recently updated
    return [str(f) for f in file_paths]


def load_json(path):
    try:
        with open(path) as context:
            return json.load(context)
    except ValueError:
        logger.log(TRACE, f"Exception occur when loading JSON: {path}. Skip.")


def read_config(path):
    config = ConfigParser()
    config.read(path)
    return config


def write_config(path, config):
    with open(path, "w") as destination:
        config.write(destination)
