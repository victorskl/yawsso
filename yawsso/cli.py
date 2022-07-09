import argparse
import logging
import os
import shutil
import sys
from pathlib import Path

from yawsso import Constant, VERSION, PROGRAM, TRACE, core, extra, utils

logger = logging.getLogger(__name__)


def main():
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')  # print UNIX friendly format for PIPE use case
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    version_help = f"{PROGRAM} {VERSION}"
    description = "Sync all named profiles when calling without any arguments"
    parser = argparse.ArgumentParser(prog=PROGRAM, description=description)
    parser.add_argument("--default", action="store_true", help="Sync AWS default profile and all named profiles")
    parser.add_argument("--default-only", action="store_true", help="Sync AWS default profile only and exit")
    parser.add_argument("-p", "--profiles", nargs="*", metavar="", help="Sync specified AWS named profiles")
    parser.add_argument("-b", "--bin", metavar="", help="AWS CLI v2 binary location (default to `aws` in PATH)")
    parser.add_argument("-d", "--debug", help="Debug output", action="store_true")
    parser.add_argument("-t", "--trace", help="Trace output", action="store_true")
    parser.add_argument("-e", "--export-vars", dest="export_vars1", help="Print out AWS ENV vars", action="store_true")
    parser.add_argument("-v", "--version", help="Print version and exit", action="store_true")

    sp = parser.add_subparsers(title="available commands", metavar="", dest="command")
    login_help = "Invoke aws sso login and sync all named profiles"
    login_description = f"{login_help}\nUse `default` profile or `AWS_PROFILE` if optional argument `--profile` absent"
    login_command = sp.add_parser(
        "login", description=login_description, help=login_help, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    login_command.add_argument("-e", "--export-vars", help="Print out AWS ENV vars", action="store_true")
    login_command.add_argument("--profile", help="Login profile (use `default` or `AWS_PROFILE` if absent)", metavar="")
    login_command.add_argument("--this", action="store_true", help="Only sync this login profile")
    sp.add_parser("encrypt", help=f"Encrypt ({Constant.ROT_13.value.upper()}) stdin and exit")
    sp.add_parser("decrypt", help=f"Decrypt ({Constant.ROT_13.value.upper()}) stdin and exit")
    sp.add_parser("version", help="Print version and exit")

    args = parser.parse_args()

    if args.trace:
        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler.setFormatter(formatter)
        logger.setLevel(TRACE)
        logger.log(TRACE, "Logging level: TRACE")

    if args.debug:
        formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
        handler.setFormatter(formatter)
        logger.setLevel(logging.DEBUG)
        logger.debug("Logging level: DEBUG")

    logger.log(TRACE, f"args: {args}")
    logger.log(TRACE, f"AWS_CONFIG_FILE: {core.aws_config_file}")
    logger.log(TRACE, f"AWS_SHARED_CREDENTIALS_FILE: {core.aws_shared_credentials_file}")
    logger.log(TRACE, f"AWS_SSO_CACHE_PATH: {core.aws_sso_cache_path}")
    logger.log(TRACE, f"Cache SSO JSON files: {utils.list_directory(core.aws_sso_cache_path)}")

    # Make export_vars avail either side of subcommand
    x_vars = args.export_vars if hasattr(args, 'export_vars') and args.export_vars else False
    x_vars1 = args.export_vars1 if hasattr(args, 'export_vars1') and args.export_vars1 else False
    export_vars = x_vars or x_vars1

    if args.version:
        logger.info(version_help)
        exit(0)

    if args.bin:
        core.aws_bin = args.bin

    if not os.path.exists(core.aws_shared_credentials_file):
        logger.debug(f"{core.aws_shared_credentials_file} file does not exist. Attempting to create one.")
        try:
            Path(os.path.dirname(core.aws_shared_credentials_file)).mkdir(parents=True, exist_ok=True)
            with open(core.aws_shared_credentials_file, "w"):
                pass
        except Exception as e:
            logger.debug(f"Can not create {core.aws_shared_credentials_file}. Exception: {e}")
            utils.halt(f"{core.aws_shared_credentials_file} file does not exist. Please create one and try again.")

    if not os.path.exists(core.aws_config_file):
        utils.halt(f"{core.aws_config_file} does not exist")

    if not os.path.exists(core.aws_sso_cache_path):
        utils.halt(f"{core.aws_sso_cache_path} does not exist")

    if shutil.which(core.aws_bin) is None:
        utils.halt(f"Can not find AWS CLI v2 `{core.aws_bin}` command.")

    cmd_aws_cli_version = f"{core.aws_bin} --version"
    aws_cli_success, aws_cli_version_output = utils.invoke(cmd_aws_cli_version)

    if not aws_cli_success:
        utils.halt(f"ERROR EXECUTING COMMAND: '{cmd_aws_cli_version}'. EXCEPTION: {aws_cli_version_output}")

    if "aws-cli/2" not in aws_cli_version_output:
        utils.halt(f"Required AWS CLI v2. Found {aws_cli_version_output}")

    logger.debug(aws_cli_version_output)

    config = utils.read_config(core.aws_config_file)

    profiles_new_name = dict()

    if args.command:
        if args.command == "version":
            logger.info(version_help)
            exit(0)

        elif args.command == "encrypt":
            for line in sys.stdin:
                print(extra.encrypt(line.rstrip("\n")))
            exit(0)

        elif args.command == "decrypt":
            for line in sys.stdin:
                print(extra.decrypt(line.rstrip("\n")))
            exit(0)

        elif args.command == "login":
            login_profile = "default"
            login_profile_new_name = ""
            cmd_aws_sso_login = f"{core.aws_bin} sso login"

            if args.profile:
                if ":" in args.profile:
                    login_profile, login_profile_new_name = args.profile.split(":")
                    profiles_new_name[login_profile] = login_profile_new_name
                else:
                    login_profile = args.profile

                cmd_aws_sso_login = f"{cmd_aws_sso_login} --profile={login_profile}"

            logger.log(TRACE, f"Running command: `{cmd_aws_sso_login}`")

            login_success = utils.poll(cmd_aws_sso_login, output=not export_vars)
            if not login_success:
                utils.halt(f"Error running command: `{cmd_aws_sso_login}`")

            # Specific use case: making `yawsso login -e` or `yawsso login --profile NAME -e`
            # to login, sync, print cred then exit
            if export_vars:
                credentials = core.update_profile(login_profile, config, login_profile_new_name)
                extra.get_export_vars(login_profile, credentials)
                exit(0)

            if args.this:
                core.update_profile(login_profile, config, login_profile_new_name)
                exit(0)

            if login_profile == "default" and not export_vars:
                core.update_profile("default", config, login_profile_new_name)

            # otherwise continue with sync all named profiles below

    # Specific use case: making `yawsso -e` behaviour to sync default profile, print cred then exit
    if export_vars and not args.default and not args.profiles and not hasattr(args, 'profile'):
        credentials = core.update_profile("default", config)
        extra.get_export_vars("default", credentials)
        exit(0)

    # Specific use case: two flags to take care of default profile sync behaviour
    if args.default or args.default_only:
        credentials = core.update_profile("default", config)
        if export_vars:
            extra.get_export_vars("default", credentials)
        if args.default_only:
            exit(0)

    named_profiles = list(map(lambda p: p.replace("profile ", ""), filter(lambda s: s != "default", config.sections())))
    if len(named_profiles) > 0:
        logger.debug(f"Current named profiles in config: {str(named_profiles)}")

    core.profiles = named_profiles

    if args.profiles:
        profiles = []
        for np in args.profiles:
            if ":" in np:
                old, new = np.split(":")
                if old not in named_profiles:
                    logger.warning(f"Named profile `{old}` is not specified in {core.aws_config_file}. Skipping...")
                    continue
                logger.debug(f"Renaming profile {old} to {new}")
                profiles.append(old)
                profiles_new_name[old] = new
            elif np.endswith("*"):
                prefix = np.split("*")[0]
                logger.log(TRACE, f"Collecting all named profiles start with '{prefix}'")
                for _p in named_profiles:
                    if _p.startswith(prefix):
                        profiles.append(_p)
            else:
                if np not in named_profiles:
                    logger.warning(f"Named profile `{np}` is not specified in {core.aws_config_file}. Skipping...")
                    continue
                profiles.append(np)
        core.profiles = list(set(profiles))  # dedup
        logger.debug(f"Syncing named profiles: {core.profiles}")

    for profile_name in core.profiles:
        if profile_name in profiles_new_name:
            credentials = core.update_profile(profile_name, config, profiles_new_name[profile_name])
        else:
            credentials = core.update_profile(profile_name, config)
        if export_vars:
            extra.get_export_vars(profile_name, credentials)
