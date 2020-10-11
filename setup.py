from setuptools import setup

from yawsso import __version__

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="yawsso",
    version=__version__,
    description="Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/victorskl/yawsso",
    author="Victor San Kho Lin",
    author_email="victor@sankholin.com",
    license="MIT",
    packages=["yawsso"],
    zip_safe=False,
    entry_points={
        "console_scripts": ["yawsso=yawsso.cli:main"],
    },
    extras_require={
        "all": [
            "pyperclip",
        ],
        "test": [
            "pytest",
            "pytest-cov",
            "flake8",
            "mockito",
            "cli-test-helpers",
            "nose2",
            "coveralls",
            "pyperclip==1.7.0",
        ],
        "dev": [
            "twine",
            "setuptools",
            "wheel",
        ],
    },
    python_requires=">=3.6",
)
