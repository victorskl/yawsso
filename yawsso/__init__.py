"""yawsso cli package"""
import logging
from enum import Enum
from pathlib import Path

# versioning follow PEP440
__version__ = VERSION = '1.2.0'  # pragma: no cover

PROGRAM = 'yawsso'  # pragma: no cover

TRACE = 5
logging.addLevelName(TRACE, 'TRACE')
logger = logging.getLogger(__name__)


class Constant(Enum):
    ROLE_CHAINING_DURATION_SECONDS = 3600
    AWS_SSO_CACHE_PATH = f"{Path.home()}/.aws/sso/cache"
    AWS_CONFIG_FILE = f"{Path.home()}/.aws/config"
    AWS_SHARED_CREDENTIALS_FILE = f"{Path.home()}/.aws/credentials"
    AWS_DEFAULT_REGION = "us-east-1"
    ROT_13 = "rot13"
    VERSION_HELP = f"{PROGRAM} {VERSION}"
