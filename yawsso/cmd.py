import sys
from abc import ABC, abstractmethod

from yawsso import TRACE, Constant, logger, core, utils


class Command(object):

    def __init__(self, args):
        self.args = args
        self.config = utils.read_config(core.aws_config_file)
        self.profiles_new_name = dict()
        self.export_vars = self._build_export_vars()

    def _build_export_vars(self):
        """Make export_vars avail either side of subcommand"""
        x_vars = self.args.export_vars if hasattr(self.args, 'export_vars') and self.args.export_vars else False
        x_vars1 = self.args.export_vars1 if hasattr(self.args, 'export_vars1') and self.args.export_vars1 else False
        return x_vars or x_vars1

    def dispatch(self):
        if self.args.command == "version":
            logger.info(Constant.VERSION_HELP.value)
            exit(0)

        elif self.args.command == "encrypt":
            EncryptCommand(self).perform()

        elif self.args.command == "decrypt":
            DecryptCommand(self).perform()

        elif self.args.command == "login":
            LoginCommand(self).perform()


class CommandAction(ABC):

    def __init__(self, co: Command):
        self.co = co

    @abstractmethod
    def perform(self):
        pass  # pragma: no cover


class EncryptCommand(CommandAction):

    def perform(self):
        for line in sys.stdin:
            print(utils.encrypt(line.rstrip("\n")))
        exit(0)


class DecryptCommand(CommandAction):

    def perform(self):
        for line in sys.stdin:
            print(utils.decrypt(line.rstrip("\n")))
        exit(0)


class LoginCommand(CommandAction):

    def perform(self):
        login_profile = "default"
        login_profile_new_name = ""
        cmd_aws_sso_login = f"{core.aws_bin} sso login"

        if self.co.args.profile:
            if ":" in self.co.args.profile:
                # support rename profile upon login then sync use case
                login_profile, login_profile_new_name = self.co.args.profile.split(":")
                self.co.profiles_new_name[login_profile] = login_profile_new_name
            else:
                login_profile = self.co.args.profile

            cmd_aws_sso_login = f"{cmd_aws_sso_login} --profile={login_profile}"

        logger.log(TRACE, f"Running command: `{cmd_aws_sso_login}`")

        login_success = utils.poll(cmd_aws_sso_login, output=not self.co.export_vars)
        if not login_success:
            utils.halt(f"Error running command: `{cmd_aws_sso_login}`")

        # Specific use case: making `yawsso login -e` or `yawsso login --profile NAME -e`
        # to perform login, sync, print cred then exit
        if self.co.export_vars:
            credentials = core.update_profile(login_profile, self.co.config, login_profile_new_name)
            utils.get_export_vars(login_profile, credentials)
            exit(0)

        if self.co.args.this:
            core.update_profile(login_profile, self.co.config, login_profile_new_name)
            exit(0)

        if login_profile == "default" and not self.co.export_vars:
            core.update_profile("default", self.co.config, login_profile_new_name)
