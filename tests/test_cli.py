import json
import logging
import os
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
        self.config = tempfile.NamedTemporaryFile(delete=False)
        conf_ini = b"""
        [sso-session petshop]
        sso_start_url = https://petshop.awsapps.com/start
        sso_region = ap-southeast-2
        sso_registration_scopes = sso:account:access
        
        [profile dev2]
        sso_session = petshop
        sso_account_id = 123456789123
        sso_role_name = AdministratorAccess
        region = ap-southeast-2
        output = json
        cli_pager =
        
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

        self.credentials = tempfile.NamedTemporaryFile(delete=False)
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
        self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.json', delete=False)
        cache_json = {
            "startUrl": "https://petshop.awsapps.com/start",
            "region": "ap-southeast-2",
            "accessToken": "longTextA.AverylOngText",
            "expiresAt": f"{str((datetime.utcnow() + timedelta(hours=3)).isoformat())[:-7]}UTC",
            "clientId": "longTextA",
            "clientSecret": "longTextA",  # pragma: allowlist secret
            "refreshToken": "longTextA"   # pragma: allowlist secret
        }
        self.sso_cache_json.write(json.dumps(cache_json).encode('utf-8'))
        self.sso_cache_json.seek(0)
        self.sso_cache_json.read()

        cli.core.aws_config_file = self.config.name
        cli.core.aws_shared_credentials_file = self.credentials.name
        cli.core.aws_sso_cache_path = self.sso_cache_dir.name

        mock_output = {
            'roleCredentials':
                {
                    'accessKeyId': 'does-not-matter',
                    'secretAccessKey': '',
                    'sessionToken': 'VeryLongBase664String==',
                    'expiration': datetime.utcnow().timestamp()
                }
        }

        mock_assume_role = {
            "Credentials": {
                "AccessKeyId": "does-not-matter",
                "SecretAccessKey": "",
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

        mock_ok = True
        mock_cli_v2 = 'aws-cli/2.7.10 Python/3.9.13 Darwin/21.5.0 source/x86_64 prompt/off (MOCK)'
        when(cli.utils).invoke(contains('aws --version')).thenReturn((mock_ok, mock_cli_v2))
        when(cli.utils).invoke(contains('aws sts get-caller-identity')).thenReturn((mock_ok, 'does-not-matter'))
        when(cli.utils).invoke(contains('aws sso get-role-credentials')).thenReturn((mock_ok, json.dumps(mock_output)))
        when(cli.utils).invoke(contains('aws iam get-role')).thenReturn((mock_ok, json.dumps(mock_get_role)))
        when(cli.utils).invoke(contains('aws sts assume-role')).thenReturn((mock_ok, json.dumps(mock_assume_role)))

    def tearDown(self) -> None:
        self.config.close()
        self.credentials.close()
        self.sso_cache_json.close()

        if os.path.exists(self.config.name):
            os.unlink(self.config.name)

        if os.path.exists(self.credentials.name):
            os.unlink(self.credentials.name)

        if os.path.exists(self.sso_cache_json.name):
            os.unlink(self.sso_cache_json.name)

        self.sso_cache_dir.cleanup()
        cli.core.aws_bin = "aws"
        unstub()

    def test_main(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_main
        """
        with ArgvContext(program, '-p', 'dev', '--debug'):
            cli.main()
            cred = cli.utils.read_config(self.credentials.name)
            new_tok = cred['dev']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli.utils, times=2).invoke(...)

    def test_sso_session_config(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_sso_session_config
        """
        with ArgvContext(program, '-p', 'dev2', '--debug'):
            cli.main()
            cred = cli.utils.read_config(self.credentials.name)
            new_tok = cred['dev2']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli.utils, times=2).invoke(...)

    def test_sso_session_config_no_section(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_sso_session_config_no_section
        """
        with ArgvContext(program, '-p', 'dev2', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
            conf_ini = b"""
            [profile dev2]
            sso_session = petshop
            sso_account_id = 123456789123
            sso_role_name = AdministratorAccess
            region = ap-southeast-2
            output = json
            cli_pager =
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.core.aws_config_file = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)
        verify(cli.utils, times=1).invoke(...)

    def test_profile_prefix(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_profile_prefix
        """
        with ArgvContext(program, '-p', 'lab*', 'lab', 'zzz', '--trace'):
            cli.main()
            cred = cli.utils.read_config(self.credentials.name)
            new_tok = cred['lab']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            self.assertEqual(4, len(cli.core.profiles))
            verify(cli.utils, times=4).invoke(...)

    def test_not_sso_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_not_sso_profile
        """
        with ArgvContext(program, '-p', 'dev', '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
            conf_ini = b"""
            [profile dev]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.core.aws_config_file = self.config.name
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli.utils, times=1).invoke(...)

    def test_invalid_bin(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_invalid_bin
        """
        with ArgvContext(program, '-b', f'/usr/local/bin/aws{randint(3, 9)}', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_profile_not_found(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_profile_not_found
        """
        with ArgvContext(program, '-p', uuid.uuid4().hex, '-t'):
            cli.main()
        self.assertEqual(len(cli.core.profiles), 0)

    def test_config_not_found(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_config_not_found
        """
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.core.aws_config_file = "mock.config"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_credential_not_found(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_credential_not_found
        """
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_name = tmp_file.name
        tmp_file.close()
        os.unlink(tmp_file.name)
        with ArgvContext(program, '-d', '-p', 'dev'):
            cli.core.aws_shared_credentials_file = tmp_name
            cli.main()
        cred = cli.utils.read_config(cli.core.aws_shared_credentials_file)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')

    def test_credential_not_found_2(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_credential_not_found_2
        """
        when(pathlib.Path).mkdir(...).thenRaise(Exception("mock.credentials.file.exception"))
        with ArgvContext(program, '-d', '-p', 'dev'), self.assertRaises(SystemExit) as x:
            cli.core.aws_shared_credentials_file = "mock.credentials"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_found(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_sso_cache_not_found
        """
        with ArgvContext(program, '-t'), self.assertRaises(SystemExit) as x:
            cli.core.aws_sso_cache_path = "mock.sso.cache.json"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_aws_cli_v1(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_aws_cli_v1
        """
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            mock_cli_v1 = 'aws-cli/1.18.61 Python/2.7.17 Linux/5.3.0-1020-azure botocore/1.16.11 (MOCK v1)'
            when(cli.utils).invoke(contains('aws --version')).thenReturn((True, mock_cli_v1))
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_default_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_default_profile
        """
        with ArgvContext(program, '--default-only', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
            conf_ini = b"""
            [default]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.core.aws_config_file = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_no_such_profile_section(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_no_such_profile_section
        """
        with ArgvContext(program, '--default', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
            conf_ini = b"""
            [profile default]
            region = ap-southeast-2
            output = json
            """
            self.config.write(conf_ini)
            self.config.seek(0)
            self.config.read()
            cli.core.aws_config_file = self.config.name
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_json(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_sso_cache_not_json
        """
        with ArgvContext(program, '-p', 'dev', '-t'):
            # clean up as going to mutate this
            self.sso_cache_json.close()
            os.unlink(self.sso_cache_json.name)
            self.sso_cache_dir.cleanup()
            # start new test case
            self.sso_cache_dir = tempfile.TemporaryDirectory()
            self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.txt', delete=False)
            self.sso_cache_json.seek(0)
            self.sso_cache_json.read()
            cli.core.aws_sso_cache_path = self.sso_cache_dir.name
            cli.main()

    def test_not_equal_sso_start_url(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_not_equal_sso_start_url
        """
        with ArgvContext(program, '-p', 'dev', '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()

    def test_not_equal_sso_region(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_not_equal_sso_region
        """
        with ArgvContext(program, '-p', 'dev', '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        sso_cache = cli.utils.load_json(self.sso_cache_json.name)
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')  # assert cred updated
        # self.assertEqual(cred['dev']['region'], 'us-east-2')  # assert cred region is same as config region issue#76
        self.assertEqual(sso_cache['region'], 'ap-southeast-2')  # assert sso cache is in another region pr#61
        verify(cli.utils, times=2).invoke(...)

    def test_load_json_value_error(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_load_json_value_error
        """
        # clean up as going to mutate this
        self.sso_cache_json.close()
        os.unlink(self.sso_cache_json.name)
        self.sso_cache_dir.cleanup()
        # start new test case
        self.sso_cache_dir = tempfile.TemporaryDirectory()
        self.sso_cache_json = tempfile.NamedTemporaryFile(dir=self.sso_cache_dir.name, suffix='.json', delete=False)
        self.sso_cache_json.write('{}{}'.encode('utf-8'))
        self.sso_cache_json.seek(0)
        self.sso_cache_json.read()
        output = cli.utils.load_json(self.sso_cache_json.name)
        logger.info(output)
        self.assertIsNone(output)

    def test_sso_get_role_credentials_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_sso_get_role_credentials_fail
        """
        when(cli.utils).invoke(contains('aws sso get-role-credentials')).thenReturn((False, 'does-not-matter'))
        when(cli.utils).invoke(contains('aws sso-oidc create-token')).thenReturn((False, 'does-not-matter'))
        cred = cli.core.update_profile("dev", cli.utils.read_config(self.config.name))
        self.assertIsNone(cred)

    def test_aws_cli_version_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_aws_cli_version_fail
        """
        when(cli.utils).invoke(contains('aws --version')).thenReturn((False, 'does-not-matter'))
        with ArgvContext(program, '-p', 'dev', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_source_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_source_profile
        """
        with ArgvContext(program, '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=4).invoke(...)

    def test_source_profile_region_mismatch(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_source_profile_region_mismatch
        """
        with ArgvContext(program, '-t', '-p', 'dev'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'VeryLongBase664String==')  # assert cross region is allowed and cred updated PR#61
        verify(cli.utils, times=4).invoke(...)

    def test_source_profile_eager_sync(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_source_profile_eager_sync
        """
        with ArgvContext(program, '-t', '-p', 'dev'):
            self.credentials.close()
            os.unlink(self.credentials.name)
            self.credentials = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_shared_credentials_file = self.credentials.name

            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=4).invoke(...)

    def test_eager_sync_source_profile_should_skip(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_eager_sync_source_profile_should_skip
        """
        cli.core.profiles = ["default"]
        self.assertIsNone(cli.core.eager_sync_source_profile("default", {}))

    def test_source_profile_not_sso(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_source_profile_not_sso
        """
        with ArgvContext(program, '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli.utils, times=1).invoke(...)

    def test_print_export_vars(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_print_export_vars
        """
        with ArgvContext(program, '-e', '-p', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=2).invoke(...)

    def test_print_export_vars_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_print_export_vars_fail
        """
        when(cli.core).update_profile(...).thenReturn(None)
        with ArgvContext(program, '-e', '-t', '-p', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli.utils, times=1).invoke(...)

    def test_print_export_vars_default_only_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_print_export_vars_default_only_profile
        """
        with ArgvContext(program, '-e', '-t'), self.assertRaises(SystemExit) as x:
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        verify(cli.utils, times=2).invoke(...)
        self.assertEqual(x.exception.code, 0)

    def test_print_export_vars_default_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_print_export_vars_default_profile
        """
        with ArgvContext(program, '-e', '--default', '-t'):
            # clean up as going to mutate this
            self.config.close()
            os.unlink(self.config.name)
            # now start new test case
            self.config = tempfile.NamedTemporaryFile(delete=False)
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
            cli.core.aws_config_file = self.config.name
            cli.main()
        verify(cli.utils, times=2).invoke(...)

    def test_clipboard_export_vars(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_clipboard_export_vars
        """
        with ArgvContext(program, '-d', '-e', '-p', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=2).invoke(...)

    def test_clipboard_export_vars_2(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_clipboard_export_vars_2
        """
        when(cli.utils.importlib_util).find_spec("pyperclip").thenReturn(None)
        with ArgvContext(program, '-t', '-e', '-p', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=2).invoke(...)

    def test_parse_credentials_file_session_expiry(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_parse_credentials_file_session_expiry
        """
        expires_utc = cli.core.parse_credentials_file_session_expiry("2020-06-14T17:13:26+0000")
        self.assertIsNotNone(expires_utc)

    def test_version_flag(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_version_flag
        """
        with ArgvContext(program, '-v', '-t'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_get_role_max_session_duration_no_success(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_get_role_max_session_duration_no_success
        """
        when(cli.utils).invoke(contains('aws iam get-role')).thenReturn((False, "does-not-matter"))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1'}
        duration_seconds = cli.core.get_role_max_session_duration("default", p)
        self.assertEqual(3600, duration_seconds)

    def test_fetch_credentials_with_assume_role_no_success(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_fetch_credentials_with_assume_role_no_success
        """
        when(cli.utils).invoke(contains('aws sts assume-role')).thenReturn((False, "does-not-matter"))
        when(cli.utils).invoke(contains('aws iam get-role')).thenReturn((True, '{"Role": {"MaxSessionDuration": 3600}}'))
        p = {'role_arn': 'arn:aws:iam::1234567890:role/FullAdmin', 'region': 'us-east-1', 'source_profile': 'default'}
        cred = cli.core.fetch_credentials_with_assume_role("default", p)
        self.assertIsNone(cred)

    def test_login_command(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_login_command_default(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_default
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        when(os).getenv(...).thenReturn('default')
        with ArgvContext(program, '-t', 'login'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_login_command_this(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_this
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev', '--this'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_login_command_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_fail
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(False)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev', '--this'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)
        cred = cli.utils.read_config(self.credentials.name)
        tok_now = cred['dev']['aws_session_token']
        self.assertEqual(tok_now, 'tok')  # assert no update
        verify(cli.utils, times=1).invoke(...)

    def test_login_command_export_vars(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_export_vars
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        when(os).getenv(...).thenReturn('default')
        with ArgvContext(program, '-t', 'login', '-e'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_login_command_export_vars_2(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_export_vars_2
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        when(os).getenv(...).thenReturn('default')
        with ArgvContext(program, '-t', '-e', 'login'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['default']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_version_command(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_version_command
        """
        with ArgvContext(program, 'version'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    def test_unknown_command(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_unknown_command
        """
        with ArgvContext(program, uuid.uuid4().hex), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 2)

    # below are subprocess cmd call tests, better keep them at last

    def test_invoke_cmd_success(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_invoke_cmd_success
        """
        unstub()
        success, output = cli.utils.invoke("aws --version")
        logger.info(output)
        self.assertTrue(success)

    def test_invoke_cmd_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_invoke_cmd_fail
        """
        unstub()
        mock_proc_error = cli.utils.subprocess.CalledProcessError(1, "aws space get-mars", b"me-sah, jar jar binks!")
        when(cli.utils.subprocess).check_output(...).thenRaise(mock_proc_error)
        success, output = cli.utils.invoke("aws space get-mars")
        logger.info(output)
        self.assertTrue(not success)

    def test_poll_cmd_success(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_poll_cmd_success
        """
        unstub()
        mock_proc = mock(cli.utils.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: []
        when(cli.utils.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.utils.Poll("aws space get-lunar").start().resolve()
        self.assertTrue(success)

    def test_poll_cmd_fail(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_poll_cmd_fail
        """
        unstub()
        mock_proc = mock(cli.utils.subprocess.Popen)
        mock_proc.stdout = mock()
        mock_proc.stderr = mock()
        mock_proc.stdout.readline = lambda: print('sky walker\nlight saber\nEOF')
        mock_proc.stderr.readlines = lambda: ['ka-boom!']
        when(cli.utils.subprocess).Popen(...).thenReturn(mock_proc)
        success = cli.utils.Poll("aws space get-moon").start().resolve()
        self.assertTrue(not success)

    def test_xu(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_xu
        """
        a = cli.utils.xu('~/tmp')
        b = f"{pathlib.Path.home()}/tmp"
        logger.info(f"A: {a}")
        logger.info(f"B: {b}")
        self.assertEqual(a, b)

    def test_ca_bundle(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_ca_bundle
        """
        with ArgvContext(program, '-p', 'ca_bundle', '-t'):
            cli.main()
            cred = cli.utils.read_config(self.credentials.name)
            new_tok = cred['ca_bundle']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli.utils, times=2).invoke(...)

    def test_append_cli_global_options(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_append_cli_global_options
        """
        ca_bundle_profile = cli.core.load_profile_from_config("ca_bundle", cli.utils.read_config(self.config.name))
        cmd = cli.core.append_cli_global_options("aws sso get-role-credentials", ca_bundle_profile)
        logger.info(cmd)
        self.assertIn('--ca-bundle', cmd)

    def test_rename_profile(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_rename_profile
        """
        with ArgvContext(program, '-p', 'dev:dev_renamed', '--trace'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev_renamed']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=2).invoke(...)

    def test_rename_profile_not_found(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_rename_profile_not_found
        """
        with ArgvContext(program, '-p', f"{uuid.uuid4().hex}:new_name", '-t'):
            cli.main()
        self.assertEqual(len(cli.core.profiles), 0)

    def test_login_command_rename(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_login_command_rename
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)
        with ArgvContext(program, '-t', 'login', '--profile', 'dev:dev_renamed'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev_renamed']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_region_flag(self):
        """
        python -m unittest tests.test_cli.CLIUnitTests.test_region_flag
        """
        with ArgvContext(program, '-p', 'dev', '-t', '-r'):
            cli.main()
            cred = cli.utils.read_config(self.credentials.name)
            new_tok = cred['dev']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            self.assertEqual(cred['dev']['region'], 'ap-southeast-2')
            verify(cli.utils, times=2).invoke(...)
