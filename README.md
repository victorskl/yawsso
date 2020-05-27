# yawsso

![Pull Request Build Status](https://github.com/victorskl/yawsso/workflows/Pull%20Request%20Build/badge.svg)

Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials.

This tool is originally based on [aws_sso.py](https://gist.github.com/sgtoj/af0ed637b1cc7e869b21a62ef56af5ac) script but take different approach and depends only on AWS CLI v2 for [get-role-credentials](https://awscli.amazonaws.com/v2/documentation/api/latest/reference/sso/get-role-credentials.html). Well, everything else fail (including boto3, see below) except CLI itself, so...

## Prerequisite

- Required [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- Assume you have already setup [AWS SSO](https://aws.amazon.com/single-sign-on/) for your organization

## TL;DR

- Install like so:
```commandline
pip install yawsso
```

- Do your per normal login like so:
```commandline
aws configure sso
aws sso login --profile=dev
```

- To sync for `default` profile, just:
```commandline
yawsso
```

- To sync for named profile, do:
```commandline
yawsso -p dev
```

- Then, continue with your normal tool. 
    - i.e. `cdk deploy ...` or `terraform ...` or `cw ls -p dev groups`, so on so ford...

- To print help:
```commandline
yawsso -h
```

## Why

AWS CLI v2 SSO login cache/store credentials is somewhat different to AWS CLI v1 i.e. no longer in `~/.aws/credentials`. There are many SDK and tools still depends on this legacy `~/.aws/credentials` format.

- boto3 - https://github.com/boto/boto3/issues/2091
- terraform aws provider - https://github.com/terraform-providers/terraform-provider-aws/issues/10851
- cdk - https://github.com/aws/aws-cdk/issues/5455
- cw - https://github.com/lucagrulla/cw/issues/119
- awsbw - https://github.com/jgolob/awsbw

And, https://github.com/aws/aws-cli/issues/4982 in CLI repo itself!!

Someday, we won't need this anymore. But, until then this tool sync up AWS CLI v2 SSO login session to legacy format auto-magically!!

## Others

If this tools is not working for you, try the following:

- https://github.com/benkehoe/aws-sso-credential-process
- https://gist.github.com/sgtoj/af0ed637b1cc7e869b21a62ef56af5ac
- https://github.com/flyinprogrammer/aws-sso-fetcher

## Test

- Create virtual environment and then:

```
pip install '.[test]' .
pytest
python -m unittest
```

- Create issue or pull request welcome

## License

MIT License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
