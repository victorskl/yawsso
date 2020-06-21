import json
import logging
import tempfile
import uuid
from datetime import datetime, timedelta
from random import randint
from unittest import TestCase

from cli_test_helpers import ArgvContext
from mockito import unstub, when, contains, verify, mock

from yawsso import cli

handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

program = 'yawsso'


class CLIUnitTests(TestCase):

    def setUp(self) -> None:
        self.config = tempfile.NamedTemporaryFile()
        conf_ini = b"""
        [default]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 9876543210
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json
        
        [profile dev]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 123456789
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json
        """
        self.config.write(conf_ini)
        self.config.seek(0)
        self.config.read()

        self.credentials = tempfile.NamedTemporaryFile()
        cred_ini = b"""
        [default]
        region = ap-southeast-2
        aws_access_key_id = MOCK
        aws_secret_access_key  = MOCK
        aws_session_token = tok
        aws_session_expiration = 2020-05-27T18:21:43+0000

        [dev]
        region = ap-southeast-2
        aws_access_key_id = MOCK
        aws_secret_access_key  = MOCK
        aws_session_token = tok
        aws_session_expiration = 2020-05-27T18:21:43+0000
        """
        self.credentials.write(cred_ini)
        self.credentials.seek(0)
        self.credentials.read()

        self.sso_cache_dir = tempfile.TemporaryDirectory()
        self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.json')
        cache_json = {
            "startUrl": "https://petshop.awsapps.com/start",
            "region": "ap-southeast-2",
            "accessToken": "longTextA.AverylOngText",
            "expiresAt": f"{str((datetime.utcnow() + timedelta(hours=3)).isoformat())[:-7]}UTC"
        }
        self.sso_cache_json.write(json.dumps(cache_json).encode('utf-8'))
        self.sso_cache_json.seek(0)
        self.sso_cache_json.read()

        cli.AWS_CONFIG_PATH = self.config.name
        cli.AWS_CREDENTIAL_PATH = self.credentials.name
        cli.AWS_SSO_CACHE_PATH = self.sso_cache_dir.name

        mock_output = {
            'roleCredentials':
                {
                    'accessKeyId': 'does-not-matter',
                    'secretAccessKey': 'does-not-matter',
                    'sessionToken': 'VeryLongBase664String==',
                    'expiration': datetime.utcnow().timestamp()
                }
        }

        mock_assume_role = {
            "Credentials": {
                "AccessKeyId": "does-not-matter",
                "SecretAccessKey": "does-not-matter",
                "SessionToken": "VeryLongBase664String==",
                "Expiration": "2020-06-13T17:15:23+00:00"
            },
            "AssumedRoleUser": {
                "AssumedRoleId": "does-not-matter:yawsso-session-1",
                "Arn": "arn:aws:sts::456789123:assumed-role/FullAdmin/yawsso-session-1"
            }
        }

        mock_get_role = {
            "Role": {
                "Path": "/",
                "RoleName": "FullAdmin",
                "RoleId": "does-not-matter",
                "Arn": "arn:aws:iam::456789123:role/FullAdmin",
                "CreateDate": "2019-04-29T04:40:43+00:00",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::123456789:root"
                            },
                            "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "MaxSessionDuration": 43200,
                "RoleLastUsed": {
                    "LastUsedDate": "2020-06-14T02:27:18+00:00",
                    "Region": "ap-southeast-2"
                }
            }
        }

        mock_success = True
        mock_cli_v2 = 'aws-cli/2.0.9 Python/3.8.2 Darwin/19.4.0 botocore/2.0.0dev13 (MOCK)'
        when(cli).invoke(contains('aws --version')).thenReturn((mock_success, mock_cli_v2))
        when(cli).invoke(contains('aws sts get-caller-identity')).thenReturn((mock_success, 'does-not-matter'))
        when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((mock_success, json.dumps(mock_output)))
        when(cli).invoke(contains('aws iam get-role')).thenReturn((mock_success, json.dumps(mock_get_role)))
        when(cli).invoke(contains('aws sts assume-role')).thenReturn((mock_success, json.dumps(mock_assume_role)))

    def tearDown(self) -> None:
        self.config.close()
        self.credentials.close()
        self.sso_cache_json.close()
        self.sso_cache_dir.cleanup()
        cli.aws_bin = "aws"
        unstub()

    def test_main(self):
        with ArgvContext(program, '-p', 'dev', '--debug'):
            cli.main()
            cred = cli.read_config(self.credentials.name)
            new_tok = cred['dev']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli, times=3).invoke(...)

    def test_not_sso_profile(self):
        with ArgvContext(program, '-p', 'dev', '-t'):
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [profile dev]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli, times=1).invoke(...)

    def test_invalid_bin(self):
        with ArgvContext(program, '-b', f'/usr/local/bin/aws{randint(3, 9)}', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_profile_not_found(self):
        with ArgvContext(program, '-p', uuid.uuid4().hex, '-t'):
            cli.main()
        self.assertEqual(len(cli.profiles), 0)

    def test_config_not_found(self):
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.AWS_CONFIG_PATH = "mock.config"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_credential_not_found(self):
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.AWS_CREDENTIAL_PATH = "mock.credentials"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_found(self):
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.AWS_SSO_CACHE_PATH = "mock.sso.cache.json"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_expires(self):
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.sso_cache_json.close()
            self.sso_cache_dir.cleanup()
            # start new test case
            self.sso_cache_dir = tempfile.TemporaryDirectory()
            self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.json')
            cache_json = {
                "startUrl": "https://petshop.awsapps.com/start",
                "region": "ap-southeast-2",
                "accessToken": "longTextA.AverylOngText",
                "expiresAt": f"{str((datetime.utcnow()).isoformat())[:-7]}UTC"
            }
            self.sso_cache_json.write(json.dumps(cache_json).encode('utf-8'))
            self.sso_cache_json.seek(0)
            self.sso_cache_json.read()
            cli.AWS_SSO_CACHE_PATH = self.sso_cache_dir.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_aws_cli_v1(self):
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            mock_cli_v1 = 'aws-cli/1.18.61 Python/2.7.17 Linux/5.3.0-1020-azure botocore/1.16.11 (MOCK v1)'
            when(cli).invoke(contains('aws --version')).thenReturn((True, mock_cli_v1))
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_default_profile(self):
        with ArgvContext(program, '--default-only', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_no_such_profile_section(self):
        with ArgvContext(program, '--default', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [profile default]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_json(self):
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.sso_cache_json.close()
            self.sso_cache_dir.cleanup()
            # start new test case
            self.sso_cache_dir = tempfile.TemporaryDirectory()
            self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.txt')
            self.sso_cache_json.seek(0)
            self.sso_cache_json.read()
            cli.AWS_SSO_CACHE_PATH = self.sso_cache_dir.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_not_equal_sso_start_url(self):
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [profile dev]
            sso_start_url = https://vetclinic.awsapps.com/start
            sso_region = ap-southeast-2
            sso_account_id = 123456789
            sso_role_name = AdministratorAccess
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_not_equal_sso_region(self):
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [profile dev]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = us-east-2
            sso_account_id = 123456789
            sso_role_name = AdministratorAccess
            region = us-east-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_load_json_value_error(self):
        # clean up as going to mutate this
        self.sso_cache_json.close()
        self.sso_cache_dir.cleanup()
        # start new test case
        self.sso_cache_dir = tempfile.TemporaryDirectory()
        self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.json')
        self.sso_cache_json.write('{}{}'.encode('utf-8'))
        self.sso_cache_json.seek(0)
        self.sso_cache_json.read()
        output = cli.load_json(self.sso_cache_json.name)
        logger.info(output)
        self.assertIsNone(output)

    def test_sts_get_caller_identity_fail(self):
        when(cli).invoke(contains('aws sts get-caller-identity')).thenReturn((False, 'does-not-matter'))
        with self.assertRaises(SystemExit) as x:
            cli.update_profile("dev", cli.read_config(self.config.name))
        self.assertEqual(x.exception.code, 1)

    def test_sso_get_role_credentials_fail(self):
        when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((False, 'does-not-matter'))
        with self.assertRaises(SystemExit) as x:
            cli.update_profile("dev", cli.read_config(self.config.name))
        self.assertEqual(x.exception.code, 1)

    def test_aws_cli_version_fail(self):
        when(cli).invoke(contains('aws --version')).thenReturn((False, 'does-not-matter'))
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_source_profile(self):
        with ArgvContext(program, '-t'):
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = ap-southeast-2
            sso_account_id = 123456789
            sso_role_name = Engineering
            region = ap-southeast-2
            output = json
            
            [profile dev]
            role_arn = arn:aws:iam::456789123:role/FullAdmin
            source_profile = default
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=6).invoke(...)

    def test_source_profile_region_mismatch(self):
        with ArgvContext(program, '-t', '-p', 'dev'):
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = us-east-1
            sso_account_id = 123456789
            sso_role_name = Engineering
            region = us-east-1
            output = json

            [profile dev]
            role_arn = arn:aws:iam::456789123:role/FullAdmin
            source_profile = default
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli, times=1).invoke(...)

    def test_source_profile_eager_sync(self):
        with ArgvContext(program, '-t', '-p', 'dev'):
            self.credentials.close()
            self.credentials = tempfile.NamedTemporaryFile()
            cred_ini = b"""
            [default]
            region = ap-southeast-2
            aws_access_key_id = MOCK
            aws_secret_access_key  = MOCK
            aws_session_token = tok
            aws_session_expiration = 2020-05-27T18:21:43+0000
            """
            self.credentials.write(cred_ini)
            self.credentials.seek(0)
            self.credentials.read()
            cli.AWS_CREDENTIAL_PATH = self.credentials.name

            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = ap-southeast-2
            sso_account_id = 123456789
            sso_role_name = Engineering
            region = ap-southeast-2
            output = json

            [profile dev]
            role_arn = arn:aws:iam::456789123:role/FullAdmin
            source_profile = default
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=6).invoke(...)

    def test_eager_sync_source_profile_should_skip(self):
        cli.profiles = ["default"]
        self.assertIsNone(cli.eager_sync_source_profile("default", {}))

    def test_source_profile_not_sso(self):
        with ArgvContext(program, '-t'):
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            region = ap-southeast-2
            output = json

            [profile dev]
            role_arn = arn:aws:iam::456789123:role/FullAdmin
            source_profile = default
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli, times=1).invoke(...)

    def test_print_export_vars(self):
        with ArgvContext(program, '-e', '-p', 'dev'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=3).invoke(...)

    def test_print_export_vars_fail(self):
        when(cli).update_profile(...).thenReturn(None)
        with ArgvContext(program, '-e', '-t', '-p', 'dev'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli, times=1).invoke(...)

    def test_print_export_vars_default_only_profile(self):
        with ArgvContext(program, '-e', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = ap-southeast-2
            sso_account_id = 123456789
            sso_role_name = Engineering
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        verify(cli, times=3).invoke(...)
        self.assertEqual(x.exception.code, 0)

    def test_print_export_vars_default_profile(self):
        with ArgvContext(program, '-e', '--default', '-t'):
            # clean up as going to mutate this
            self.config.close()
            # now start new test case
            self.config = tempfile.NamedTemporaryFile()
            conf_ini = b"""
            [default]
            sso_start_url = https://petshop.awsapps.com/start
            sso_region = ap-southeast-2
            sso_account_id = 123456789
            sso_role_name = Engineering
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.AWS_CONFIG_PATH = self.config.name
            cli.main()
        verify(cli, times=3).invoke(...)

    def test_parse_credentials_file_session_expiry(self):
        expires_utc = cli.parse_credentials_file_session_expiry("2020-06-14T17:13:26+0000")
        self.assertIsNotNone(expires_utc)

    def test_version_flag(self):
        with ArgvContext(program, '-v', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_fetch_credentials_with_assume_role_no_success_1(self):
        when(cli).invoke(contains('aws iam get-role')).thenReturn((False, "does-not-matter"))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1'}
        with self.assertRaises(SystemExit) as x:
            cli.fetch_credentials_with_assume_role("default", p)
        self.assertEqual(x.exception.code, 1)

    def test_fetch_credentials_with_assume_role_no_success_2(self):
        when(cli).invoke(contains('aws sts assume-role')).thenReturn((False, "does-not-matter"))
        when(cli).invoke(contains('aws iam get-role')).thenReturn((True, '{"Role": {"MaxSessionDuration": 3600}}'))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1'}
        with self.assertRaises(SystemExit) as x:
            cli.fetch_credentials_with_assume_role("default", p)
        self.assertEqual(x.exception.code, 1)

    def test_login_command(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)

    def test_login_command_default(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', 'login'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)

    def test_login_command_this(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev', '--this'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)

    def test_login_command_fail(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(False)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev', '--this'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli, times=1).invoke(...)

    def test_login_command_export_vars(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '-e'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)

    def test_login_command_export_vars_2(self):
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', '-e', 'login'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)

    def test_version_command(self):
        with ArgvContext(program, 'version'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_unknown_command(self):
        with ArgvContext(program, uuid.uuid4().hex), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 2)

    # below are subprocess cmd call tests, better keep them at last

    def test_invoke_cmd_success(self):
        unstub()
        success, output = cli.invoke(f"aws --version")
        logger.info(output)
        self.assertTrue(success)

    def test_invoke_cmd_fail(self):
        unstub()
        mock_proc_error = cli.subprocess.CalledProcessError(1, "aws space get-mars", b"me-sah, jar jar binks!")
        when(cli.subprocess).check_output(...).thenRaise(mock_proc_error)
        success, output = cli.invoke(f"aws space get-mars")
        logger.info(output)
        self.assertTrue(not success)

    def test_poll_cmd_success(self):
        unstub()
        mock_proc = mock(cli.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: list()
        when(cli.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.poll(f"aws space get-lunar")
        self.assertTrue(success)

    def test_poll_cmd_fail(self):
        unstub()
        mock_proc = mock(cli.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: ['ka-boom!']
        when(cli.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.poll(f"aws space get-moon")
        self.assertTrue(not success)
