import argparse
import importlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
from configparser import ConfigParser, NoSectionError
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import yawsso

TRACE = 5
logging.addLevelName(TRACE, 'TRACE')
logger = logging.getLogger(__name__)


class Constant(Enum):
    ROLE_CHAINING_DURATION_SECONDS = 3600
    AWS_SSO_CACHE_PATH = f"{Path.home()}/.aws/sso/cache"
    AWS_CONFIG_FILE = f"{Path.home()}/.aws/config"
    AWS_SHARED_CREDENTIALS_FILE = f"{Path.home()}/.aws/credentials"
    AWS_DEFAULT_REGION = "us-east-1"


def xu(path):
    if str(path).startswith('~'):
        return os.path.expanduser(path)
    else:
        return path


aws_bin = "aws"  # assume `aws` command avail in PATH and is v2. otherwise, allow mutation with -b flag
profiles = None
aws_sso_cache_path = xu(os.getenv("AWS_SSO_CACHE_PATH", Constant.AWS_SSO_CACHE_PATH.value))
aws_config_file = xu(os.getenv("AWS_CONFIG_FILE", Constant.AWS_CONFIG_FILE.value))
aws_shared_credentials_file = xu(os.getenv("AWS_SHARED_CREDENTIALS_FILE", Constant.AWS_SHARED_CREDENTIALS_FILE.value))
aws_default_region = os.getenv("AWS_DEFAULT_REGION", Constant.AWS_DEFAULT_REGION.value)


def get_aws_cli_v2_sso_cached_login(profile):
    file_paths = list_directory(aws_sso_cache_path)
    for file_path in file_paths:
        if not file_path.endswith('.json'):
            logger.log(TRACE, f"Not JSON file, skip: {file_path}")
            continue

        data = load_json(file_path)
        if data.get("startUrl") != profile["sso_start_url"]:
            logger.log(TRACE, f"Not equal SSO start url, skip: {file_path}")
            continue
        if data.get("region") != profile["sso_region"]:
            logger.log(TRACE, f"Not equal SSO region, skip: {file_path}")
            continue
        logger.log(TRACE, f"Using cached SSO login: {file_path}")
        return data


def update_aws_cli_v1_credentials(profile_name, profile, credentials):
    region = profile.get("region", aws_default_region)
    config = read_config(aws_shared_credentials_file)
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
    write_config(aws_shared_credentials_file, config)


def get_export_vars(profile_name, credentials):
    pyperclip_spec = importlib.util.find_spec("pyperclip")
    pyperclip_found = pyperclip_spec is not None

    if credentials:
        clipboard = f"export AWS_ACCESS_KEY_ID={credentials['accessKeyId']}\n"
        clipboard += f"export AWS_SECRET_ACCESS_KEY={credentials['secretAccessKey']}\n"
        clipboard += f"export AWS_SESSION_TOKEN={credentials['sessionToken']}"
        if pyperclip_found:
            import pyperclip
            pyperclip.copy(clipboard)
            logger.info(f"Credentials copied to your clipboard for profile '{profile_name}'")
        else:
            logger.debug("Clipboard module pyperclip is not installed, showing credentials on terminal instead")
            print(clipboard)  # print is intentional, i.e. not to clutter with logger
    else:
        logger.debug(f"No credentials found to export for profile '{profile_name}'")


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
        line = line.rstrip('\n')    # pragma: no cover
        if line != "" and output:   # pragma: no cover
            logger.info(line)       # pragma: no cover

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


def parse_sso_cached_login_expiry(cached_login):
    datetime_format_in_sso_cached_login = "%Y-%m-%dT%H:%M:%SUTC"
    expires_utc = datetime.strptime((cached_login["expiresAt"]), datetime_format_in_sso_cached_login)
    return expires_utc


def parse_assume_role_credentials_expiry(dt_str):
    datetime_format_in_assume_role_expiration = "%Y-%m-%dT%H:%M:%S+00:00"
    expires_utc = datetime.strptime(dt_str, datetime_format_in_assume_role_expiration)
    return expires_utc


def parse_credentials_file_session_expiry(dt_str):
    datetime_format_in_cred_file_aws_session_expiration = "%Y-%m-%dT%H:%M:%S+0000"  # 2020-06-14T17:13:26+0000
    expires_utc = datetime.strptime(dt_str, datetime_format_in_cred_file_aws_session_expiration)
    return expires_utc


def parse_role_name_from_role_arn(role_arn):
    arr = role_arn.split('/')
    return arr[len(arr) - 1]


def check_sso_cached_login_expires(profile_name, profile):
    cached_login = get_aws_cli_v2_sso_cached_login(profile)
    try:
        assert cached_login is not None, f"Can not find valid AWS CLI v2 SSO login cache in {aws_sso_cache_path}."
    except AssertionError as e:
        halt(e)

    expires_utc = parse_sso_cached_login_expiry(cached_login)

    if datetime.utcnow() > expires_utc:
        halt(f"Current cached SSO login is expired since {expires_utc.astimezone().isoformat()}. Try login again.")

    cmd_sts_get_caller_identity = f"{aws_bin} sts get-caller-identity " \
                                  f"--output json " \
                                  f"--region {profile['sso_region']} " \
                                  f"--profile {profile_name}"

    caller_success, caller_output = invoke(cmd_sts_get_caller_identity)

    if not caller_success:
        halt(f"Error executing command: `{aws_bin} sts get-caller-identity`. Exception: {caller_output}")

    return cached_login


def fetch_credentials(profile_name, profile):
    cached_login = check_sso_cached_login_expires(profile_name, profile)

    cmd_get_role_cred = f"{aws_bin} sso get-role-credentials " \
                        f"--output json " \
                        f"--profile {profile_name} " \
                        f"--region {profile['sso_region']} " \
                        f"--role-name {profile['sso_role_name']} " \
                        f"--account-id {profile['sso_account_id']} " \
                        f"--access-token {cached_login['accessToken']}"

    role_cred_success, role_cred_output = invoke(cmd_get_role_cred)

    if not role_cred_success:
        logger.log(TRACE, f"Command was: {cmd_get_role_cred}")
        logger.log(TRACE, f"Output  was: {role_cred_output}")
        halt(f"Error executing command: `{aws_bin} sso get-role-credentials`. Possibly SSO login session has expired. "
             f"Try login again. Exception: {role_cred_output}")

    return json.loads(role_cred_output)['roleCredentials']


def get_role_max_session_duration(profile_name, profile):
    role_name = parse_role_name_from_role_arn(profile['role_arn'])

    cmd_get_role = f"{aws_bin} iam get-role " \
                   f"--output json " \
                   f"--profile {profile_name} " \
                   f"--role-name {role_name} " \
                   f"--region {profile['region']}"

    get_role_success, get_role_output = invoke(cmd_get_role)

    if not get_role_success:
        logger.log(TRACE, f"Command was: {cmd_get_role}")
        logger.log(TRACE, f"Output  was: {get_role_output}")
        halt(f"Error executing command: `{aws_bin} iam get-role`. Exception: {get_role_output}")

    return json.loads(get_role_output)['Role']['MaxSessionDuration']


def fetch_credentials_with_assume_role(profile_name, profile):
    duration_seconds = get_role_max_session_duration(profile_name, profile)
    if duration_seconds > Constant.ROLE_CHAINING_DURATION_SECONDS.value:
        logger.log(TRACE, f"Role {profile['role_arn']} is configured with max duration `{duration_seconds}` seconds. "
                          f"But AWS SSO service-linked role to assume another role_arn defined in source_profile form "
                          f"`role chaining` (i.e. using a role to assume a second role). Fall back session duration "
                          f"to a maximum of one hour. Well, you can always `yawsso` again when session expired!")
        duration_seconds = Constant.ROLE_CHAINING_DURATION_SECONDS.value

    utc_now_ts = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
    cmd_assume_role_cred = f"{aws_bin} sts assume-role " \
                           f"--output json " \
                           f"--profile {profile_name} " \
                           f"--role-arn {profile['role_arn']} " \
                           f"--role-session-name yawsso-session-{utc_now_ts} " \
                           f"--duration-seconds {duration_seconds} " \
                           f"--region {profile['region']}"

    role_cred_success, role_cred_output = invoke(cmd_assume_role_cred)

    if not role_cred_success:
        logger.log(TRACE, f"Command was: {cmd_assume_role_cred}")
        logger.log(TRACE, f"Output  was: {role_cred_output}")
        halt(f"Error executing command: `{aws_bin} sts assume-role`. Exception: {role_cred_output}")

    assume_role_cred = json.loads(role_cred_output)['Credentials']

    _cred = {}
    _cred.update(accessKeyId=assume_role_cred['AccessKeyId'])
    _cred.update(secretAccessKey=assume_role_cred['SecretAccessKey'])
    _cred.update(sessionToken=assume_role_cred['SessionToken'])

    _expire_utc = parse_assume_role_credentials_expiry(assume_role_cred['Expiration'])
    _expire_utc_ts_millisecond = int(_expire_utc.replace(tzinfo=timezone.utc).timestamp() * 1000)
    _cred.update(expiration=_expire_utc_ts_millisecond)

    return _cred


def eager_sync_source_profile(source_profile_name, source_profile):
    if profiles and source_profile_name in profiles:  # it will come in main loop, so no proactive sync required
        return
    config = read_config(aws_shared_credentials_file)
    if config.has_section(source_profile_name):
        cred_profile = dict(config.items(source_profile_name))
        session_expires_utc = parse_credentials_file_session_expiry(cred_profile['aws_session_expiration'])
        if datetime.utcnow() > session_expires_utc:
            logger.log(TRACE, f"Eagerly sync source_profile `{source_profile_name}`")
            credentials = fetch_credentials(source_profile_name, source_profile)
            update_aws_cli_v1_credentials(source_profile_name, source_profile, credentials)


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


def is_source_profile(profile):
    return {"source_profile", "role_arn", "region"} <= profile.keys()


def update_profile(profile_name, config):
    profile = load_profile_from_config(profile_name, config)

    logger.log(TRACE, f"Syncing profile... {profile_name}: {profile}")

    if is_sso_profile(profile):
        credentials = fetch_credentials(profile_name, profile)

    elif is_source_profile(profile):
        source_profile_name = profile['source_profile']
        source_profile = load_profile_from_config(source_profile_name, config)
        if not is_sso_profile(source_profile):
            logger.warning(f"Your source_profile is not an AWS SSO profile. Skip syncing profile `{profile_name}`")
            return
        if profile['region'] != source_profile['sso_region']:
            logger.warning(f"Region mismatch with source_profile AWS SSO region. Skip syncing profile `{profile_name}`")
            return
        check_sso_cached_login_expires(source_profile_name, source_profile)
        eager_sync_source_profile(source_profile_name, source_profile)
        logger.log(TRACE, f"Fetching credentials using assume role for `{profile_name}`")
        credentials = fetch_credentials_with_assume_role(profile_name, profile)

    else:
        logger.warning(f"Not an AWS SSO profile nor no source_profile found. Skip syncing profile `{profile_name}`")
        return

    update_aws_cli_v1_credentials(profile_name, profile, credentials)

    logger.debug(f"Done syncing AWS CLI v1 credentials using AWS CLI v2 SSO login session for profile `{profile_name}`")

    return credentials


def main():
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('%(message)s')  # print UNIX friendly format for PIPE use case
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    version_help = f"{yawsso.__name__} {yawsso.__version__}"
    description = "Sync all named profiles when calling without any arguments"
    parser = argparse.ArgumentParser(prog=yawsso.__name__, description=description)
    parser.add_argument("--default", action="store_true", help=f"Sync AWS default profile and all named profiles")
    parser.add_argument("--default-only", action="store_true", help=f"Sync AWS default profile only and exit")
    parser.add_argument("-p", "--profiles", nargs="*", metavar="", help=f"Sync specified AWS named profiles")
    parser.add_argument("-b", "--bin", metavar="", help="AWS CLI v2 binary location (default to `aws` in PATH)")
    parser.add_argument("-d", "--debug", help="Debug output", action="store_true")
    parser.add_argument("-t", "--trace", help="Trace output", action="store_true")
    parser.add_argument("-e", "--export-vars", dest="export_vars1", help="Print out AWS ENV vars", action="store_true")
    parser.add_argument("-v", "--version", help="Print version and exit", action="store_true")

    sp = parser.add_subparsers(title="available commands", metavar="", dest="command")
    login_help = "Invoke aws sso login and sync all named profiles"
    login_description = f"{login_help}\nUse `default` profile if optional argument `--profile` absent"
    login_command = sp.add_parser(
        "login", description=login_description, help=login_help, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    login_command.add_argument("-e", "--export-vars", help="Print out AWS ENV vars", action="store_true")
    login_command.add_argument("--profile", help="Login profile name (use `default` if absent)", metavar="")
    login_command.add_argument("--this", action="store_true", help="Only sync this login profile")
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
    logger.log(TRACE, f"AWS_CONFIG_FILE: {aws_config_file}")
    logger.log(TRACE, f"AWS_SHARED_CREDENTIALS_FILE: {aws_shared_credentials_file}")
    logger.log(TRACE, f"AWS_SSO_CACHE_PATH: {aws_sso_cache_path}")
    logger.log(TRACE, f"Cache SSO JSON files: {list_directory(aws_sso_cache_path)}")

    # Make export_vars avail either side of subcommand
    x_vars = args.export_vars if hasattr(args, 'export_vars') and args.export_vars else False
    x_vars1 = args.export_vars1 if hasattr(args, 'export_vars1') and args.export_vars1 else False
    export_vars = x_vars or x_vars1

    if args.version:
        logger.info(version_help)
        exit(0)

    global aws_bin
    if args.bin:
        aws_bin = args.bin

    if not os.path.exists(aws_shared_credentials_file):
        logger.debug(f"{aws_shared_credentials_file} file does not exist. Attempting to create one.")
        try:
            Path(os.path.dirname(aws_shared_credentials_file)).mkdir(parents=True, exist_ok=True)
            with open(aws_shared_credentials_file, "w"):
                pass
        except Exception as e:
            logger.debug(f"Can not create {aws_shared_credentials_file}. Exception: {e}")
            halt(f"{aws_shared_credentials_file} file does not exist. Please create one and try again.")

    try:
        assert shutil.which(aws_bin) is not None, f"Can not find AWS CLI v2 `{aws_bin}` command."
        assert os.path.exists(aws_config_file), f"{aws_config_file} does not exist"
        assert os.path.exists(aws_shared_credentials_file), f"{aws_shared_credentials_file} does not exist"
        assert os.path.exists(aws_sso_cache_path), f"{aws_sso_cache_path} does not exist"
    except AssertionError as e:
        halt(e)

    cmd_aws_cli_version = f"{aws_bin} --version"
    aws_cli_success, aws_cli_version_output = invoke(cmd_aws_cli_version)

    if not aws_cli_success:
        halt(f"Error executing command: `{aws_bin} --version`. Exception: {aws_cli_version_output}")

    if "aws-cli/2" not in aws_cli_version_output:
        halt(f"Required AWS CLI v2. Found {aws_cli_version_output}")

    logger.debug(aws_cli_version_output)

    config = read_config(aws_config_file)

    if args.command:
        if args.command == "version":
            logger.info(version_help)
            exit(0)

        elif args.command == "login":
            login_profile = "default"
            cmd_aws_sso_login = f"{aws_bin} sso login"

            if args.profile:
                login_profile = args.profile

            cmd_aws_sso_login = f"{cmd_aws_sso_login} --profile={login_profile}"

            logger.log(TRACE, f"Running command: `{cmd_aws_sso_login}`")

            login_success = poll(cmd_aws_sso_login, output=not export_vars)
            if not login_success:
                halt(f"Error running command: `{cmd_aws_sso_login}`")

            # Specific use case: making `yawsso login -e` or `yawsso login --profile NAME -e`
            # to login, sync, print cred then exit
            if export_vars:
                credentials = update_profile(login_profile, config)
                get_export_vars(login_profile, credentials)
                exit(0)

            if args.this:
                update_profile(login_profile, config)
                exit(0)

            if login_profile == "default" and not export_vars:
                update_profile("default", config)

            # otherwise continue with sync all named profiles below

    # Specific use case: making `yawsso -e` behaviour to sync default profile, print cred then exit
    if export_vars and not args.default and not args.profiles and not hasattr(args, 'profile'):
        credentials = update_profile("default", config)
        get_export_vars("default", credentials)
        exit(0)

    # Specific use case: two flags to take care of default profile sync behaviour
    if args.default or args.default_only:
        credentials = update_profile("default", config)
        if export_vars:
            get_export_vars("default", credentials)
        if args.default_only:
            exit(0)

    named_profiles = list(map(lambda p: p.replace("profile ", ""), filter(lambda s: s != "default", config.sections())))
    if len(named_profiles) > 0:
        logger.debug(f"Current named profiles in config: {str(named_profiles)}")

    global profiles
    profiles = named_profiles

    if args.profiles:
        profiles = []
        for np in args.profiles:
            if np.endswith("*"):
                prefix = np.split("*")[0]
                logger.log(TRACE, f"Collecting all named profiles start with '{prefix}'")
                for _p in named_profiles:
                    if _p.startswith(prefix):
                        profiles.append(_p)
            else:
                if np not in named_profiles:
                    logger.warning(f"Named profile `{np}` is not specified in {aws_config_file} file. Skipping...")
                    continue
                profiles.append(np)
        profiles = list(set(profiles))  # dedup
        logger.debug(f"Syncing named profiles: {profiles}")

    for profile_name in profiles:
        credentials = update_profile(profile_name, config)
        if export_vars:
            get_export_vars(profile_name, credentials)
