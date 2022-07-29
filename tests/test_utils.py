import os
import platform
from unittest import TestCase

from mockito import when

from tests.test_cli import logger
from yawsso.utils import Exporter


def mock_cred():
    return {
        "accessKeyId": "mock",
        "secretAccessKey": "",      # pragma: allowlist secret
        "sessionToken": "mock"
    }


class UtilsUnitTests(TestCase):
    pass


class ExporterUnitTests(TestCase):

    def test_windows_powershell(self):
        """
        python -m unittest tests.test_utils.ExporterUnitTests.test_windows_powershell
        """
        when(platform).system().thenReturn("Windows")
        when(os).getenv(...).thenReturn("")
        clipboard = Exporter(credentials=mock_cred()).get_export_cmd()
        logger.info(f"\n{clipboard}")
        self.assertIn("$Env", clipboard)

    def test_windows_cmd(self):
        """
        python -m unittest tests.test_utils.ExporterUnitTests.test_windows_cmd
        """
        when(platform).system().thenReturn("Windows")
        when(os).getenv(...).thenReturn("$P$G")
        clipboard = Exporter(credentials=mock_cred()).get_export_cmd()
        logger.info(f"\n{clipboard}")
        self.assertIn("set", clipboard)

    def test_nix_cmd(self):
        """
        python -m unittest tests.test_utils.ExporterUnitTests.test_nix_cmd
        """
        when(platform).system().thenReturn("Nix")
        clipboard = Exporter(credentials=mock_cred()).get_export_cmd()
        logger.info(f"\n{clipboard}")
        self.assertIn("export", clipboard)
