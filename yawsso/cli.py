import argparse
import json
import logging
import os
import shlex
import shutil
import subprocess
from configparser import ConfigParser
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
            continue
        if data.get("region") != profile["sso_region"]:
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
        pass  # ignore invalid json


def read_config(path):
    config = ConfigParser()
    config.read(path)
    return config


def write_config(path, config):
    with open(path, "w") as destination:
        config.write(destination)


def main():
    logger.info(f"{yawsso.__name__} {yawsso.__version__}")

    assert shutil.which('aws') is not None, f"Can not find `aws` command. Required AWS CLI v2."

    cmd_aws_cli_version = "aws --version"
    cli_success, cli_version_output = invoke(cmd_aws_cli_version)

    if not cli_success:
        logger.error(cli_version_output)

    if "aws-cli/2" not in cli_version_output:
        logger.error(f"Required AWS CLI v2. Found {cli_version_output}")
        exit(1)

    logger.info(cli_version_output)

    assert os.path.exists(AWS_CONFIG_PATH), f"{AWS_CONFIG_PATH} does not exists"
    assert os.path.exists(AWS_CREDENTIAL_PATH), f"{AWS_CREDENTIAL_PATH} does not exists"
    assert os.path.exists(AWS_SSO_CACHE_PATH), f"{AWS_SSO_CACHE_PATH} does not exists"

    parser = argparse.ArgumentParser(prog=yawsso.__name__)
    parser.add_argument("-p", "--profile")
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

    profile_name = args.profile

    config = read_config(AWS_CONFIG_PATH)

    if profile_name:
        profile_opts = config.items(f"profile {profile_name}")
    else:
        profile_name = "default"
        profile_opts = config.items(f"{profile_name}")

    profile = dict(profile_opts)

    logger.debug(f"profile: {profile}")

    if "sso_start_url" not in profile or "sso_account_id" not in profile or "sso_role_name" not in profile:
        logger.error(f"Your `{profile_name}` profile configuration is not valid AWS SSO profile. "
                     f"Try `aws configure sso` first.")
        exit(1)

    cached_login = get_aws_cli_v2_sso_cached_login(profile)

    expires = datetime.strptime((cached_login["expiresAt"]), "%Y-%m-%dT%H:%M:%SUTC")

    if datetime.utcnow() > expires:
        logger.error(f"Current cached SSO login is already expired since {expires.astimezone().isoformat()}")
        logger.info(f"Please try login again: `aws sso login --profile={profile_name}`")
        exit(1)

    cmd_sts_get_caller_identity = f"aws sts get-caller-identity " \
                                  f"--output json " \
                                  f"--region {profile['sso_region']} " \
                                  f"--profile {profile_name}"
    caller_success, caller_output = invoke(cmd_sts_get_caller_identity)

    if not caller_success:
        logger.error(caller_output)
        exit(1)

    cmd_get_role_cred = f"aws sso get-role-credentials " \
                        f"--output json " \
                        f"--profile {profile_name} " \
                        f"--region {profile['sso_region']} " \
                        f"--role-name {profile['sso_role_name']} " \
                        f"--account-id {profile['sso_account_id']} " \
                        f"--access-token {cached_login['accessToken']}"

    role_cred_success, role_cred_output = invoke(cmd_get_role_cred)

    if not role_cred_success:
        logger.error(f"Error executing command: `aws sso get-role-credentials`. "
                     f"Use --debug flag for more verbose output.")
        logger.debug(f"Command was: {cmd_get_role_cred}")
        logger.debug(f"Output  was: {role_cred_output}")
        exit(1)

    credentials = json.loads(role_cred_output)['roleCredentials']

    update_aws_cli_v1_credentials(profile_name, profile, credentials)

    logger.info(f"Done syncing up AWS CLI v1 credentials using AWS CLI v2 SSO login session")
