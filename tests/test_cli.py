import json
import tempfile
import uuid
from datetime import datetime, timedelta
from random import randint
from unittest import TestCase

from cli_test_helpers import ArgvContext
from mockito import unstub, when, contains, verify

from . import logger
from yawsso import cli

program = 'yawsso'


class CLIUnitTests(TestCase):

    def setUp(self) -> None:
        self.config = tempfile.NamedTemporaryFile()
        conf_ini = b"""
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
                    'accessKeyId': 'AAAA4IGTCPYNIZGVJCVW',
                    'secretAccessKey': '00GGc0cDG6WzbJIcDlw/gh0BaMOCKK0M/qDtDxR1',
                    'sessionToken': 'VeryLongBase664String==',
                    'expiration': datetime.utcnow().timestamp()
                }
        }
        mock_success = True
        mock_cli_v2 = 'aws-cli/2.0.9 Python/3.8.2 Darwin/19.4.0 botocore/2.0.0dev13 (MOCK)'
        when(cli).invoke(contains('aws --version')).thenReturn((mock_success, mock_cli_v2))
        when(cli).invoke(contains('aws sts get-caller-identity')).thenReturn((mock_success, 'does-not-matter'))
        when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((mock_success, json.dumps(mock_output)))

    def tearDown(self) -> None:
        self.config.close()
        self.credentials.close()
        self.sso_cache_json.close()
        self.sso_cache_dir.cleanup()
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
        with ArgvContext(program, '-p', 'dev', '-d'):
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
        with ArgvContext(program, '-b', f'/usr/local/bin/aws{randint(3, 9)}', '-d'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_profile_not_found(self):
        with ArgvContext(program, '-p', uuid.uuid4().hex, '-d'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_config_not_found(self):
        with ArgvContext(program, '-d'), self.assertRaises(SystemExit) as x:
            cli.AWS_CONFIG_PATH = "mock.config"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_credential_not_found(self):
        with ArgvContext(program, '-d'), self.assertRaises(SystemExit) as x:
            cli.AWS_CREDENTIAL_PATH = "mock.credentials"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_not_found(self):
        with ArgvContext(program, '-d'), self.assertRaises(SystemExit) as x:
            cli.AWS_SSO_CACHE_PATH = "mock.sso.cache.json"
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_sso_cache_expires(self):
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
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
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
            mock_cli_v1 = 'aws-cli/1.18.61 Python/2.7.17 Linux/5.3.0-1020-azure botocore/1.16.11 (MOCK v1)'
            when(cli).invoke(contains('aws --version')).thenReturn((True, mock_cli_v1))
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_default_profile(self):
        with ArgvContext(program, '--default-only', '-d'), self.assertRaises(SystemExit) as x:
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
        with ArgvContext(program, '--default', '-d'), self.assertRaises(SystemExit) as x:
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
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
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
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
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
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
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

    def test_invoke_cmd_fail(self):
        unstub()
        success, output = cli.invoke(f"aws sts get-caller-identity")  # FIXME need to run under unauthenticated test env
        logger.info(output)
        self.assertTrue(not success)

    def test_invoke_cmd_success(self):
        unstub()
        success, output = cli.invoke(f"aws --version")
        logger.info(output)
        self.assertTrue(success)

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
            cli.update_profile("dev", cli.read_config(self.config.name), "aws")
        self.assertEqual(x.exception.code, 1)

    def test_sso_get_role_credentials_fail(self):
        when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((False, 'does-not-matter'))
        with self.assertRaises(SystemExit) as x:
            cli.update_profile("dev", cli.read_config(self.config.name), "aws")
        self.assertEqual(x.exception.code, 1)

    def test_aws_cli_version_fail(self):
        when(cli).invoke(contains('aws --version')).thenReturn((False, 'does-not-matter'))
        with ArgvContext(program, '-p', 'dev', '-d'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_source_profile(self):
        with ArgvContext(program, '-d'):
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
            
            [profile qc]
            role_arn = arn:aws:iam::789123456:role/FullAdmin
            source_profile = default
            region = ap-southeast-2
            output = json
            
            [profile prod]
            role_arn = arn:aws:iam::987654321:role/DevOps
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
        verify(cli, times=7).invoke(...)

    def test_source_profile_not_sso(self):
        with ArgvContext(program, '-d'):
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
