from setuptools import setup

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="yawsso",
    # version="MOVE TO setup.cfg",
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
    project_urls={
        "Bug Tracker": "https://github.com/victorskl/yawsso/issues",
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
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
            "coveralls",
            "pyperclip",
        ],
        "dev": [
            "twine",
            "setuptools",
            "wheel",
            "build",
            "aws-cdk-lib",
            "constructs",
            "tox",
            "nose2",
            "pre-commit",
            "detect-secrets",
            "ggshield",
        ],
    },
    python_requires=">=3.6",
)
