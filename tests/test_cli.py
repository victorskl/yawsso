import json
import logging
import pathlib
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

        [profile zzz]
        region = ap-southeast-2
        output = json
        cli_pager = 

        [profile lab]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 923456781
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json

        [profile lab1]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 9874567321
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json

        [profile lab2]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 983456721
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json
        
        [profile ca_bundle]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_account_id = 123456789
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json
        ca_bundle = dev/apps/ca-certs/cabundle-2019mar05.pem        
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

        cli.aws_config_file = self.config.name
        cli.aws_shared_credentials_file = self.credentials.name
        cli.aws_sso_cache_path = self.sso_cache_dir.name

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
            verify(cli, times=2).invoke(...)

    def test_profile_prefix(self):
        with ArgvContext(program, '-p', 'lab*', 'lab', 'zzz', '--trace'):
            cli.main()
            cred = cli.read_config(self.credentials.name)
            new_tok = cred['lab']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            self.assertEqual(4, len(cli.profiles))
            verify(cli, times=4).invoke(...)

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
            cli.aws_config_file = self.config.name
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
            cli.aws_config_file = "mock.config"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_credential_not_found(self):
        tmp_file = tempfile.NamedTemporaryFile()
        tmp_name = tmp_file.name
        tmp_file.close()
        with ArgvContext(program, '-d', '-p', 'dev'):
            cli.aws_shared_credentials_file = tmp_name
            cli.main()
        cred = cli.read_config(cli.aws_shared_credentials_file)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')

    def test_credential_not_found_2(self):
        when(pathlib.Path).mkdir(...).thenRaise(Exception("mock.credentials.file.exception"))
        with ArgvContext(program, '-d', '-p', 'dev'), self.assertRaises(SystemExit) as x:
            cli.aws_shared_credentials_file = "mock.credentials"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_found(self):
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.aws_sso_cache_path = "mock.sso.cache.json"
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
            cli.aws_sso_cache_path = self.sso_cache_dir.name
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
            cli.aws_config_file = self.config.name
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
            cli.aws_config_file = self.config.name
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
            cli.aws_sso_cache_path = self.sso_cache_dir.name
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
            cli.aws_config_file = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_not_equal_sso_region(self):
        with ArgvContext(program, '-p', 'dev', '-t'):
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
            cli.aws_config_file = self.config.name
            cli.main()
        sso_cache = cli.load_json(self.sso_cache_json.name)
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')     # assert cred updated
        self.assertEqual(cred['dev']['region'], 'us-east-2')     # assert cred region is same as config region
        self.assertEqual(sso_cache['region'], 'ap-southeast-2')  # assert sso cache is in another region
        verify(cli, times=2).invoke(...)

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

    def test_sso_get_role_credentials_fail(self):
        when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((False, 'does-not-matter'))
        cred = cli.update_profile("dev", cli.read_config(self.config.name))
        self.assertIsNone(cred)

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
            cli.aws_config_file = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=4).invoke(...)

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
            cli.aws_config_file = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')  # assert cross region is allowed and cred updated
        verify(cli, times=4).invoke(...)

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
            cli.aws_shared_credentials_file = self.credentials.name

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
            cli.aws_config_file = self.config.name
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=4).invoke(...)

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
            cli.aws_config_file = self.config.name
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
        verify(cli, times=2).invoke(...)

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
            cli.aws_config_file = self.config.name
            cli.main()
        verify(cli, times=2).invoke(...)
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
            cli.aws_config_file = self.config.name
            cli.main()
        verify(cli, times=2).invoke(...)

    def test_clipboard_export_vars(self):
        with ArgvContext(program, '-d', '-e', '-p', 'dev'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=2).invoke(...)

    def test_clipboard_export_vars_2(self):
        when(cli.importlib_util).find_spec("pyperclip").thenReturn(None)
        with ArgvContext(program, '-t', '-e', '-p', 'dev'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=2).invoke(...)

    def test_parse_credentials_file_session_expiry(self):
        expires_utc = cli.parse_credentials_file_session_expiry("2020-06-14T17:13:26+0000")
        self.assertIsNotNone(expires_utc)

    def test_version_flag(self):
        with ArgvContext(program, '-v', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_get_role_max_session_duration_no_success(self):
        when(cli).invoke(contains('aws iam get-role')).thenReturn((False, "does-not-matter"))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1'}
        duration_seconds = cli.get_role_max_session_duration("default", p)
        self.assertEqual(3600, duration_seconds)

    def test_fetch_credentials_with_assume_role_no_success(self):
        when(cli).invoke(contains('aws sts assume-role')).thenReturn((False, "does-not-matter"))
        when(cli).invoke(contains('aws iam get-role')).thenReturn((True, '{"Role": {"MaxSessionDuration": 3600}}'))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1'}
        cred = cli.fetch_credentials_with_assume_role("default", p)
        self.assertIsNone(cred)

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
        success, output = cli.invoke("aws --version")
        logger.info(output)
        self.assertTrue(success)

    def test_invoke_cmd_fail(self):
        unstub()
        mock_proc_error = cli.subprocess.CalledProcessError(1, "aws space get-mars", b"me-sah, jar jar binks!")
        when(cli.subprocess).check_output(...).thenRaise(mock_proc_error)
        success, output = cli.invoke("aws space get-mars")
        logger.info(output)
        self.assertTrue(not success)

    def test_poll_cmd_success(self):
        unstub()
        mock_proc = mock(cli.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: []
        when(cli.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.poll("aws space get-lunar")
        self.assertTrue(success)

    def test_poll_cmd_fail(self):
        unstub()
        mock_proc = mock(cli.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: ['ka-boom!']
        when(cli.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.poll("aws space get-moon")
        self.assertTrue(not success)

    def test_xu(self):
        a = cli.xu('~/tmp')
        b = f"{pathlib.Path.home()}/tmp"
        logger.info(f"A: {a}")
        logger.info(f"B: {b}")
        self.assertEqual(a, b)

    def test_ca_bundle(self):
        with ArgvContext(program, '-p', 'ca_bundle', '-t'):
            cli.main()
            cred = cli.read_config(self.credentials.name)
            new_tok = cred['ca_bundle']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli, times=2).invoke(...)

    def test_append_cli_global_options(self):
        ca_bundle_profile = cli.load_profile_from_config("ca_bundle", cli.read_config(self.config.name))
        cmd = cli.append_cli_global_options("aws sso get-role-credentials", ca_bundle_profile)
        logger.info(cmd)
        self.assertIn('--ca-bundle', cmd)

    def test_rename_profile(self):
        with ArgvContext(program, '-p', 'dev:dev_renamed', '--debug'):
            cli.main()
            cred = cli.read_config(self.credentials.name)
            new_tok = cred['dev_renamed']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli, times=2).invoke(...)

    def test_rename_profile_not_found(self):
        with ArgvContext(program, '-p', f"{uuid.uuid4().hex}:new_name", '-t'):
            cli.main()
        self.assertEqual(len(cli.profiles), 0)

    def test_login_command_rename(self):   
        when(cli).poll(contains('aws sso login'), ...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev:dev_renamed'):
            cli.main()
        cred = cli.read_config(self.credentials.name)
        new_tok = cred['dev_renamed']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli, times=1).poll(...)
