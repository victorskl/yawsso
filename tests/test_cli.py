import json
import tempfile
from datetime import datetime, timedelta
from unittest import TestCase

from cli_test_helpers import ArgvContext
from mockito import unstub, when, contains, verify

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

    def tearDown(self) -> None:
        self.config.close()
        self.credentials.close()
        self.sso_cache_json.close()
        self.sso_cache_dir.cleanup()
        unstub()

    def test_main(self):
        with ArgvContext(program, '-p', 'dev', '--debug'):
            cli.AWS_CONFIG_PATH = self.config.name
            cli.AWS_CREDENTIAL_PATH = self.credentials.name
            cli.AWS_SSO_CACHE_PATH = self.sso_cache_dir.name

            output = {
                'roleCredentials':
                    {
                        'accessKeyId': '***REMOVED***',
                        'secretAccessKey': '***REMOVED***',
                        'sessionToken': 'VeryLongBase664String==',
                        'expiration': datetime.utcnow().timestamp()
                    }
            }
            success = True
            cli_v2 = 'aws-cli/2.0.9 Python/3.8.2 Darwin/19.4.0 botocore/2.0.0dev13 (MOCK)'
            when(cli).invoke(contains('aws --version')).thenReturn((success, cli_v2))
            when(cli).invoke(contains('aws sts get-caller-identity')).thenReturn((success, 'does-not-matter'))
            when(cli).invoke(contains('aws sso get-role-credentials')).thenReturn((success, json.dumps(output)))

            cli.main()

            cred = cli.read_config(self.credentials.name)
            new_tok = cred['dev']['aws_session_token']
            self.assertNotEqual(new_tok, 'tok')
            self.assertEqual(new_tok, 'VeryLongBase664String==')
            verify(cli, times=3).invoke(...)
