import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
from configparser import ConfigParser, NoSectionError
from datetime import datetime
from pathlib import Path

import yawsso

AWS_CONFIG_PATH = f"{Path.home()}/.aws/config"
AWS_CREDENTIAL_PATH = f"{Path.home()}/.aws/credentials"
AWS_SSO_CACHE_PATH = f"{Path.home()}/.aws/sso/cache"
AWS_DEFAULT_REGION = "us-east-1"

handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def get_aws_cli_v2_sso_cached_login(profile):
    file_paths = list_directory(AWS_SSO_CACHE_PATH)
    for file_path in file_paths:
        if not file_path.endswith('.json'):
            logger.debug(f"Not JSON file, skip: {file_path}")
            continue

        data = load_json(file_path)
        if data.get("startUrl") != profile["sso_start_url"]:
            logger.debug(f"Not equal SSO start url, skip: {file_path}")
            continue
        if data.get("region") != profile["sso_region"]:
            logger.debug(f"Not equal SSO region, skip: {file_path}")
            continue
        logger.debug(f"Using cached SSO login: {file_path}")
        return data


def update_aws_cli_v1_credentials(profile_name, profile, credentials):
    region = profile.get("region", AWS_DEFAULT_REGION)
    config = read_config(AWS_CREDENTIAL_PATH)
    if config.has_section(profile_name):
        config.remove_section(profile_name)
    config.add_section(profile_name)
    config.set(profile_name, "region", region)
    config.set(profile_name, "aws_access_key_id", credentials["accessKeyId"])
    config.set(profile_name, "aws_secret_access_key ", credentials["secretAccessKey"])
    config.set(profile_name, "aws_session_token", credentials["sessionToken"])
    ts_expires_millisecond = credentials["expiration"]
    dt_utc = str(datetime.utcfromtimestamp(ts_expires_millisecond / 1000.0).isoformat() + '+0000')
    config.set(profile_name, "aws_session_expiration", dt_utc)
    write_config(AWS_CREDENTIAL_PATH, config)


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
        logger.debug(f"Exception occur when loading JSON: {path}. Skip.")
        pass  # ignore invalid json


def read_config(path):
    config = ConfigParser()
    config.read(path)
    return config


def write_config(path, config):
    with open(path, "w") as destination:
        config.write(destination)


def fetch_credentials(profile_name, profile, aws_bin):
    cached_login = get_aws_cli_v2_sso_cached_login(profile)
    try:
        assert cached_login is not None, f"Can not find valid AWS CLI v2 SSO login cache in {AWS_SSO_CACHE_PATH}."
    except AssertionError as e:
        halt(e)

    expires_utc = datetime.strptime((cached_login["expiresAt"]), "%Y-%m-%dT%H:%M:%SUTC")  # datetime format in sso cache

    if datetime.utcnow() > expires_utc:
        halt(f"Current cached SSO login is expired since {expires_utc.astimezone().isoformat()}. Try login again.")

    cmd_sts_get_caller_identity = f"{aws_bin} sts get-caller-identity " \
                                  f"--output json " \
                                  f"--region {profile['sso_region']} " \
                                  f"--profile {profile_name}"

    caller_success, caller_output = invoke(cmd_sts_get_caller_identity)

    if not caller_success:
        halt(f"Error executing command: `{aws_bin} sts get-caller-identity`. Exception: {caller_output}")

    cmd_get_role_cred = f"{aws_bin} sso get-role-credentials " \
                        f"--output json " \
                        f"--profile {profile_name} " \
                        f"--region {profile['sso_region']} " \
                        f"--role-name {profile['sso_role_name']} " \
                        f"--account-id {profile['sso_account_id']} " \
                        f"--access-token {cached_login['accessToken']}"

    role_cred_success, role_cred_output = invoke(cmd_get_role_cred)

    if not role_cred_success:
        logger.debug(f"Command was: {cmd_get_role_cred}")
        logger.debug(f"Output  was: {role_cred_output}")
        halt(f"Error executing command: `{aws_bin} sso get-role-credentials`. Exception: {role_cred_output}")

    return json.loads(role_cred_output)['roleCredentials']


def load_profile_from_config(profile_name, config):
    try:
        if profile_name == "default":
            profile_opts = config.items(f"{profile_name}")
        else:
            profile_opts = config.items(f"profile {profile_name}")
        return dict(profile_opts)
    except NoSectionError as e:
        halt(e)


def is_sso_profile(profile):
    return {"sso_start_url", "sso_account_id", "sso_role_name", "sso_region"} <= profile.keys()


def update_profile(profile_name, config, aws_bin):
    profile = load_profile_from_config(profile_name, config)

    logger.debug(f"Syncing profile... {profile_name}: {profile}")

    if is_sso_profile(profile):
        credentials = fetch_credentials(profile_name, profile, aws_bin)

    elif "source_profile" in profile:
        source_profile_name = profile['source_profile']
        source_profile = load_profile_from_config(source_profile_name, config)
        if not is_sso_profile(source_profile):
            logger.warning(f"Your source_profile is not an AWS SSO profile. Skip syncing profile `{profile_name}`")
            return
        logger.debug(f"Fetching credentials using source_profile `{source_profile_name}`")
        credentials = fetch_credentials(source_profile_name, source_profile, aws_bin)

    else:
        logger.warning(f"Not an AWS SSO profile nor no source_profile found. Skip syncing profile `{profile_name}`")
        return

    update_aws_cli_v1_credentials(profile_name, profile, credentials)

    logger.info(f"Done syncing AWS CLI v1 credentials using AWS CLI v2 SSO login session for profile `{profile_name}`")


def main():
    logger.info(f"{yawsso.__name__} {yawsso.__version__}")
    description = "Sync all named profiles when calling without any arguments"
    parser = argparse.ArgumentParser(prog=yawsso.__name__, description=description)
    parser.add_argument("--default", action="store_true", help=f"Sync AWS default profile and all named profiles")
    parser.add_argument("--default-only", action="store_true", help=f"Sync AWS default profile only and exit")
    parser.add_argument("-p", "--profiles", nargs='*', metavar='', help=f"Sync specified AWS named profiles")
    parser.add_argument("-b", "--bin", metavar='', help="AWS CLI v2 binary location (default to `aws` in PATH)")
    parser.add_argument("-d", "--debug", help="Debug output", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug(f"Logging level: DEBUG")
        logger.debug(f"args: {args}")
        logger.debug(f"AWS_CONFIG_PATH: {AWS_CONFIG_PATH}")
        logger.debug(f"AWS_CREDENTIAL_PATH: {AWS_CREDENTIAL_PATH}")
        logger.debug(f"AWS_SSO_CACHE_PATH: {AWS_SSO_CACHE_PATH}")
        logger.debug(f"Cache SSO JSON files: {list_directory(AWS_SSO_CACHE_PATH)}")

    aws_bin = "aws"  # assume `aws` command avail in PATH and is v2. otherwise, allow mutation with -b flag

    if args.bin:
        aws_bin = args.bin

    try:
        assert shutil.which(aws_bin) is not None, f"Can not find AWS CLI v2 `{aws_bin}` command."
        assert os.path.exists(AWS_CONFIG_PATH), f"{AWS_CONFIG_PATH} does not exists"
        assert os.path.exists(AWS_CREDENTIAL_PATH), f"{AWS_CREDENTIAL_PATH} does not exists"
        assert os.path.exists(AWS_SSO_CACHE_PATH), f"{AWS_SSO_CACHE_PATH} does not exists"
    except AssertionError as e:
        halt(e)

    cmd_aws_cli_version = f"{aws_bin} --version"
    cli_success, cli_version_output = invoke(cmd_aws_cli_version)

    if not cli_success:
        halt(f"Error executing command: `{aws_bin} --version`. Exception: {cli_version_output}")

    if "aws-cli/2" not in cli_version_output:
        halt(f"Required AWS CLI v2. Found {cli_version_output}")

    logger.info(cli_version_output)

    config = read_config(AWS_CONFIG_PATH)

    if args.default or args.default_only:  # Specific flag to take care of default profile
        update_profile("default", config, aws_bin)
        if args.default_only:
            exit(0)

    named_profiles = list(map(lambda p: p.replace("profile ", ""), filter(lambda s: s != "default", config.sections())))
    if len(named_profiles) > 0:
        logger.info(f"Current named profiles in config: {str(named_profiles)}")

    profiles = named_profiles  # When no args pass, update all named profiles in ~/.aws/config file

    if args.profiles:  # Check if the profiles listed are in ~/.aws/config file
        profiles = []
        for np in args.profiles:
            if np in named_profiles:
                profiles.append(np)
            else:
                halt(f"Named profile `{np}` is not specified in {AWS_CONFIG_PATH} file.")

    for profile_name in profiles:
        update_profile(profile_name, config, aws_bin)
