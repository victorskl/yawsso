import json
import os
import tempfile
from io import StringIO
from unittest.mock import patch

from cli_test_helpers import ArgvContext
from mockito import when, unstub, mock, contains, verify

from tests.test_cli import CLIUnitTests, program, cli


class SetDefaultCommandUnitTests(CLIUnitTests):

    def test_set_default_command(self):
        """
        python -m unittest tests.test_cmd.SetDefaultCommandUnitTests.test_set_default_command
        """
        with ArgvContext(program, '-p', 'dev'):
            cli.main()
        cred = cli.utils.read_config(self.credentials.name)
        self.assertEqual(cred['dev']['aws_session_token'], 'VeryLongBase664String==')

        with ArgvContext(program, 'set-default', 'dev'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

        cred = cli.utils.read_config(self.credentials.name)
        self.assertEqual(cred['default']['aws_session_token'], cred['dev']['aws_session_token'])
        self.assertEqual(cred['default']['aws_access_key_id'], cred['dev']['aws_access_key_id'])

    def test_set_default_command_alias(self):
        """
        python -m unittest tests.test_cmd.SetDefaultCommandUnitTests.test_set_default_command_alias
        """
        with ArgvContext(program, '-p', 'dev'):
            cli.main()

        with ArgvContext(program, 'sd', 'dev'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 0)

        cred = cli.utils.read_config(self.credentials.name)
        self.assertEqual(cred['default']['aws_session_token'], cred['dev']['aws_session_token'])

    def test_set_default_command_profile_not_found(self):
        """
        python -m unittest tests.test_cmd.SetDefaultCommandUnitTests.test_set_default_command_profile_not_found
        """
        with ArgvContext(program, 'set-default', 'nonexistent'), self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)


class ShowAccountIdCommandUnitTests(CLIUnitTests):

    def test_show_account_id_command(self):
        """
        python -m unittest tests.test_cmd.ShowAccountIdCommandUnitTests.test_show_account_id_command
        """
        with ArgvContext(program, 'show-account-id', '--profile', 'dev'), \
                self.assertRaises(SystemExit) as x, \
                patch('sys.stdout', new_callable=StringIO) as stdout:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), '123456789')

    def test_show_account_id_command_alias(self):
        """
        python -m unittest tests.test_cmd.ShowAccountIdCommandUnitTests.test_show_account_id_command_alias
        """
        with ArgvContext(program, 'sid', '--profile', 'dev'), \
                self.assertRaises(SystemExit) as x, \
                patch('sys.stdout', new_callable=StringIO) as stdout:
            cli.main()
        self.assertEqual(x.exception.code, 0)
        self.assertEqual(stdout.getvalue().strip(), '123456789')

    def test_show_account_id_profile_not_found(self):
        """
        python -m unittest tests.test_cmd.ShowAccountIdCommandUnitTests.test_show_account_id_profile_not_found
        """
        with ArgvContext(program, 'show-account-id', '--profile', 'nonexistent'), \
                self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)

    def test_show_account_id_missing_field(self):
        """
        python -m unittest tests.test_cmd.ShowAccountIdCommandUnitTests.test_show_account_id_missing_field
        """
        with ArgvContext(program, 'show-account-id', '--profile', 'zzz'), \
                self.assertRaises(SystemExit) as x:
            cli.main()
        self.assertEqual(x.exception.code, 1)


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
