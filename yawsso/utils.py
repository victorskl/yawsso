import codecs
import json
import os
import platform
import shlex
import subprocess
from configparser import ConfigParser
from importlib import util as importlib_util
from pathlib import Path

from yawsso import TRACE, Constant, logger


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


class Poll(object):

    def __init__(self, cmd, output=True):
        self.cmd = cmd
        self.output = output

        self._proc = subprocess.Popen(
            shlex.split(self.cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

    def _out(self, line):
        if line != "" and self.output:  # pragma: no cover
            logger.info(line)  # pragma: no

    def start(self):
        while True:
            line = self._proc.stdout.readline()
            if not line:
                break
            line = line.rstrip('\n')  # pragma: no cover
            self._out(line)  # pragma: no cover
        return self

    def resolve(self):
        success = True
        for line in self._proc.stderr.readlines():
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


def encrypt(obj: str):
    return codecs.encode(obj, encoding=str(Constant.ROT_13.value))


def decrypt(obj):
    return codecs.decode(obj, encoding=str(Constant.ROT_13.value))


class Exporter(object):
    """
    https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
    """

    def __init__(self, credentials):
        self.credentials = credentials
        self.clipboard = ""

    def _make_powershell(self):
        self.clipboard = f"$Env:AWS_ACCESS_KEY_ID=\"{self.credentials['accessKeyId']}\"\n"
        self.clipboard += f"$Env:AWS_SECRET_ACCESS_KEY=\"{self.credentials['secretAccessKey']}\"\n"
        self.clipboard += f"$Env:AWS_SESSION_TOKEN=\"{self.credentials['sessionToken']}\""

    def _make_cmd(self):
        self.clipboard = f"set AWS_ACCESS_KEY_ID={self.credentials['accessKeyId']}\n"
        self.clipboard += f"set AWS_SECRET_ACCESS_KEY={self.credentials['secretAccessKey']}\n"
        self.clipboard += f"set AWS_SESSION_TOKEN={self.credentials['sessionToken']}"

    def _make_nix(self):
        self.clipboard = f"export AWS_ACCESS_KEY_ID={self.credentials['accessKeyId']}\n"
        self.clipboard += f"export AWS_SECRET_ACCESS_KEY={self.credentials['secretAccessKey']}\n"
        self.clipboard += f"export AWS_SESSION_TOKEN={self.credentials['sessionToken']}"

    def _make_windows(self):
        if os.getenv("SHELL", None):
            # bash.exe MINGW64 Git Bash
            logger.debug(f"Detected Windows platform with {os.getenv('SHELL')}")
            self._make_nix()
        elif "$P$G" in os.getenv("PROMPT", ""):
            # cmd.exe
            logger.debug(f"Detected Windows platform with cmd.exe")
            self._make_cmd()
        else:
            # powershell
            logger.debug(f"Detected Windows platform with PowerShell")
            self._make_powershell()

    def get_export_cmd(self):
        if platform.system() == "Windows":
            self._make_windows()
        else:
            # Unix
            logger.debug(f"Detected Nix platform")
            self._make_nix()

        return self.clipboard


def get_export_vars(profile_name, credentials):
    if credentials is None:
        logger.warning(f"No appropriate credentials found for profile '{profile_name}'. "
                       f"Skip exporting it. Use --trace flag to see possible error causes.")
        return

    pyperclip_spec = importlib_util.find_spec("pyperclip")
    pyperclip_found = pyperclip_spec is not None

    clipboard = Exporter(credentials).get_export_cmd()

    if pyperclip_found:
        import pyperclip  # pragma: no cover
        pyperclip.copy(clipboard)  # pragma: no cover
        logger.info(f"Credentials copied to your clipboard for profile '{profile_name}'")  # pragma: no cover
    else:
        logger.debug("Clipboard module pyperclip is not installed, showing encrypted credentials on terminal instead")
        print(encrypt(clipboard))
