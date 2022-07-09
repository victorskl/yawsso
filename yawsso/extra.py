import codecs
import logging
from importlib import util as importlib_util

from yawsso import Constant

logger = logging.getLogger(__name__)


def encrypt(obj: str):
    return codecs.encode(obj, encoding=Constant.ROT_13.value)


def decrypt(obj):
    return codecs.decode(obj, encoding=Constant.ROT_13.value)


def get_export_vars(profile_name, credentials):
    if credentials is None:
        logger.warning(f"No appropriate credentials found for profile '{profile_name}'. "
                       f"Skip exporting it. Use --trace flag to see possible error causes.")
        return

    pyperclip_spec = importlib_util.find_spec("pyperclip")
    pyperclip_found = pyperclip_spec is not None

    clipboard = f"export AWS_ACCESS_KEY_ID={credentials['accessKeyId']}\n"
    clipboard += f"export AWS_SECRET_ACCESS_KEY={credentials['secretAccessKey']}\n"
    clipboard += f"export AWS_SESSION_TOKEN={credentials['sessionToken']}"
    if pyperclip_found:
        import pyperclip  # pragma: no cover
        pyperclip.copy(clipboard)  # pragma: no cover
        logger.info(f"Credentials copied to your clipboard for profile '{profile_name}'")  # pragma: no cover
    else:
        logger.debug("Clipboard module pyperclip is not installed, showing encrypted credentials on terminal instead")
        print(encrypt(clipboard))
