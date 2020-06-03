# yawsso

[![Pull Request Build Status](https://github.com/victorskl/yawsso/workflows/Pull%20Request%20Build/badge.svg)](https://github.com/victorskl/yawsso/actions) [![codecov.io](https://codecov.io/gh/victorskl/yawsso/coverage.svg?branch=master)](https://codecov.io/gh/victorskl/yawsso?branch=master)

Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials.

## Prerequisite

- Required [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- Assume you have already setup [AWS SSO](https://aws.amazon.com/single-sign-on/) for your organization

## TL;DR

- Install [latest from PyPI](https://pypi.org/project/yawsso/) like so:
```commandline
pip install yawsso
```

- Do your per normal SSO login and, have those SSO login session cache like so:
```commandline
aws sso login --profile=dev
aws sso login --profile=prod
aws sso login --profile=stag
```

- To sync for all named profiles (e.g. dev, prod, stag), then just:
```commandline
yawsso
```

- To sync default profile, do:
```commandline
yawsso --default
```

- To sync for selected named profile, do:
```commandline
yawsso -p dev
```

- To sync for multiple selected named profiles, do:
```commandline
yawsso -p dev prod
```

- To sync for default profile as well as multiple named profiles, do:
```commandline
yawsso --default -p dev prod
```

- Then, continue per normal with your daily tools. i.e. 
    - `cdk deploy ...`
    - `terraform ...`
    - `cw ls -p dev groups`
    - `awsbw -L -P dev` 

- To print help:
```commandline
yawsso -h
```

## Why

AWS CLI v2 SSO login cache/store credentials is somewhat different to AWS CLI v1 i.e. no longer in `~/.aws/credentials`. There are many SDK and tools still depends on this legacy `~/.aws/credentials` format.

- boto3 - https://github.com/boto/boto3/issues/2091
- botocore - https://github.com/boto/botocore/issues/1988
- terraform aws provider - https://github.com/terraform-providers/terraform-provider-aws/issues/10851
- cdk - https://github.com/aws/aws-cdk/issues/5455
- cw - https://github.com/lucagrulla/cw/issues/119
- awsbw - https://github.com/jgolob/awsbw

And, https://github.com/aws/aws-cli/issues/4982 in CLI repo itself!!

This tool is originally based on [aws_sso.py](https://gist.github.com/sgtoj/af0ed637b1cc7e869b21a62ef56af5ac) script but take different approach and depends only on AWS CLI v2 for [get-role-credentials](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sso/get-role-credentials.html). Well, everything else fail (including boto3) except CLI itself, so...

Someday, we won't need this anymore. But, until then this tool sync up AWS CLI v2 SSO login session to legacy format auto-magically!!

## Others

If this tools is not working for you, try the following:

- https://github.com/benkehoe/aws-sso-credential-process
- https://github.com/flyinprogrammer/aws-sso-fetcher
- https://gist.github.com/sgtoj/af0ed637b1cc7e869b21a62ef56af5ac

## Develop

- Create virtual environment and then:

```
pip install '.[dev,test]' .
pytest
python -m unittest
python -m yawsso --debug
```

- Create issue or pull request welcome

## License

MIT License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
