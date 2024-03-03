import json
import os
import tempfile
from io import StringIO
from unittest.mock import patch

from cli_test_helpers import ArgvContext
from mockito import when, unstub, mock, contains, verify

from tests.test_cli import CLIUnitTests, program, cli


class EncryptCommandUnitTests(CLIUnitTests):

    @patch("sys.stdin", StringIO("Hello\n"))
    def test_encrypt_command(self):
        """
        python -m unittest tests.test_cmd.EncryptCommandUnitTests.test_encrypt_command
        """
        unstub()
        with ArgvContext(program, 'encrypt'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

    @patch("sys.stdin", StringIO("Uryyb\n"))
    def test_decrypt_command(self):
        """
        python -m unittest tests.test_cmd.EncryptCommandUnitTests.test_decrypt_command
        """
        unstub()
        with ArgvContext(program, 'decrypt'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)


class AutoCommandUnitTests(CLIUnitTests):

    def test_is_sso_cached_login_expired_none(self):
        """
        python -m unittest tests.test_cmd.AutoCommandUnitTests.test_is_sso_cached_login_expired_none
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)

        when(cli.cmd.AutoCommand).get_aws_cli_v2_sso_cached_login(...).thenReturn(None)

        with ArgvContext(program, '-t', 'auto', '--profile', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_auto_command(self):
        """
        python -m unittest tests.test_cmd.AutoCommandUnitTests.test_auto_command
        """
        with ArgvContext(program, '-t', 'auto', '--profile', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')

    def test_auto_command_login_expires(self):
        """
        python -m unittest tests.test_cmd.AutoCommandUnitTests.test_auto_command_login_expires
        """
        mock_poll = mock(cli.utils.Poll)
        when(cli.utils).Poll(contains('aws sso login'), ...).thenReturn(mock_poll)
        when(mock_poll).start(...).thenReturn(mock_poll)
        when(mock_poll).resolve(...).thenReturn(True)

        when(cli.cmd.AutoCommand).session_cached(...).thenReturn((False, 'does-not-matter'))
        when(cli.cmd.AutoCommand).session_refresh(...).thenReturn((False, 'does-not-matter'))

        with ArgvContext(program, '-t', 'auto', '--profile', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')
        verify(cli.utils, times=1).Poll(...)

    def test_auto_command_login_expires2(self):
        """
        python -m unittest tests.test_cmd.AutoCommandUnitTests.test_auto_command_login_expires2
        """
        when(cli.cmd.AutoCommand).session_cached(...).thenReturn((False, 'does-not-matter'))
        when(cli.utils).invoke(contains('aws sso-oidc create-token')).thenReturn((True, json.dumps({
            "accessToken": "does-not-matter",
            "tokenType": "Bearer",
            "expiresIn": 3600,
            "refreshToken": "does-not-matter"
        })))

        with ArgvContext(program, '-t', 'auto', '--profile', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        new_tok = cred['dev']['aws_session_token']
        self.assertNotEqual(new_tok, 'tok')
        self.assertEqual(new_tok, 'VeryLongBase664String==')

    def test_auto_login_not_sso_profile(self):
        """
        python -m unittest tests.test_cmd.AutoCommandUnitTests.test_auto_login_not_sso_profile
        """
        with ArgvContext(program, '-t', 'auto', '--profile', 'dev'), self.assertRaises(SystemExit) as x:
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
        self.assertEqual(x.exception.code, 1)
