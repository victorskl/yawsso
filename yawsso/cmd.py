import os
import sys
from abc import ABC, abstractmethod

from yawsso import TRACE, Constant, logger, core, utils


class Command(object):

    def __init__(self, args):
        self.args = args
        self.config = utils.read_config(core.aws_config_file)
        self._drop_sso_session_sections_from_config()
        self.profiles_new_name = dict()
        self.export_vars = self._build_export_vars()

    def _drop_sso_session_sections_from_config(self):
        sso_sessions = []
        for s in self.config.sections():
            if s.startswith("sso-session"):
                sso_sessions.append(s)
        for entry in sso_sessions:
            self.config.remove_section(entry)

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
            LoginCommand(self).perform().handle()

        elif self.args.command == "auto":
            AutoCommand(self).perform().handle()


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

    def __init__(self, co):
        super(LoginCommand, self).__init__(co)
        self.login_profile = os.getenv("AWS_PROFILE", "default")
        self.login_profile_new_name = ""
        self.cmd_aws_sso_login = f"{core.aws_bin} sso login"
        self._init_props()

    def _init_props(self):
        if self.co.args.profile:
            if ":" in self.co.args.profile:
                # support rename profile upon login then sync use case
                self.login_profile, self.login_profile_new_name = self.co.args.profile.split(":")
                self.co.profiles_new_name[self.login_profile] = self.login_profile_new_name
            else:
                self.login_profile = self.co.args.profile

            self.cmd_aws_sso_login = f"{self.cmd_aws_sso_login} --profile={self.login_profile}"

    def perform(self):
        logger.log(TRACE, f"Running command: `{self.cmd_aws_sso_login}`")

        login_success = utils.Poll(self.cmd_aws_sso_login, output=not self.co.export_vars).start().resolve()
        if not login_success:
            utils.halt(f"Error running command: `{self.cmd_aws_sso_login}`")

        return self

    def handle(self):
        """Handle is just centralised interface hook to exec all extended use cases or flags"""
        self._handle_flag_e()
        self._handle_flag_this()
        self._handle_flag_default()

    def _handle_flag_e(self):
        """
        Specific use case: making `yawsso login -e` or `yawsso login --profile NAME -e`
        to perform login, sync, print cred then exit
        """
        if self.co.export_vars:
            credentials = core.update_profile(self.login_profile, self.co.config, self.login_profile_new_name)
            utils.get_export_vars(self.login_profile, credentials)
            exit(0)

    def _handle_flag_this(self):
        if self.co.args.this:
            core.update_profile(self.login_profile, self.co.config, self.login_profile_new_name)
            exit(0)

    def _handle_flag_default(self):
        if self.login_profile == "default" and not self.co.export_vars:
            core.update_profile("default", self.co.config, self.login_profile_new_name)


class AutoCommand(LoginCommand):

    def __init__(self, co):
        super(AutoCommand, self).__init__(co)

    def session_cached(self, profile, cached_login):
        return core.session_cached(self.login_profile, profile, cached_login)

    def session_refresh(self, profile, cached_login):
        return core.session_refresh(self.login_profile, profile, cached_login)

    @staticmethod
    def get_aws_cli_v2_sso_cached_login(profile):
        return core.get_aws_cli_v2_sso_cached_login(profile)

    def perform(self):
        profile = core.load_profile_from_config(self.login_profile, self.co.config)

        if not core.is_sso_profile(profile):
            utils.halt(f"Login profile is not an AWS SSO profile. Abort auto syncing profile `{self.login_profile}`")

        cached_login = self.get_aws_cli_v2_sso_cached_login(profile)
        if cached_login is None:
            # The sso cache files may be cleared away by user or some process such as brew. Since we have proper
            # SSO login profile, just try to auto login. See https://github.com/victorskl/yawsso/issues/87
            logger.log(TRACE, f"Can not find SSO login session cache in {core.aws_sso_cache_path} "
                              f"for {profile['sso_start_url']} profile `{self.login_profile}`.")
            super(AutoCommand, self).perform()
            return self

        # try 1: attempt using cached accessToken
        role_cred_success, _ = self.session_cached(profile, cached_login)

        # try 2: attempt using refreshToken to generate accessToken
        if not role_cred_success:
            role_cred_success, _ = self.session_refresh(profile, cached_login)

        # try 3: attempt aws sso login
        if not role_cred_success:
            logger.log(TRACE, f"Your SSO login session ({profile['sso_start_url']}) has expired. Attempt auto login...")
            super(AutoCommand, self).perform()

        return self

    def handle(self):
        super(AutoCommand, self).handle()
