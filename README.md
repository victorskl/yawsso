# yawsso

[![Pull Request Build Status](https://github.com/victorskl/yawsso/workflows/Pull%20Request%20Build/badge.svg)](https://github.com/victorskl/yawsso/actions) [![Build Status](https://travis-ci.org/victorskl/yawsso.svg?branch=master)](https://travis-ci.org/victorskl/yawsso) [![codecov.io](https://codecov.io/gh/victorskl/yawsso/coverage.svg?branch=master)](https://codecov.io/gh/victorskl/yawsso?branch=master) [![Coverage Status](https://coveralls.io/repos/github/victorskl/yawsso/badge.svg?branch=master)](https://coveralls.io/github/victorskl/yawsso?branch=master) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/e02d74942ed143a381603cd60ba4f64b)](https://app.codacy.com/manual/victorskl/yawsso?utm_source=github.com&utm_medium=referral&utm_content=victorskl/yawsso&utm_campaign=Badge_Grade_Dashboard)

Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials.

## Do I need it?

- See https://github.com/victorskl/yawsso/wiki

## Prerequisite

- Required `Python >= 3.6`
- Required [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- Assume you have already setup [AWS SSO](https://aws.amazon.com/single-sign-on/) for your organization

## TL;DR

- Install [latest from PyPI](https://pypi.org/project/yawsso/) like so:
```commandline
pip install yawsso
```

- Do your per normal SSO login and, have at least one org-level SSO login session cache:
```commandline
aws sso login --profile=dev
```

- To sync for all named profiles (e.g. dev, prod, stag, ...), then just:
```commandline
yawsso
```

- To sync default profile and all named profiles, do:
```commandline
yawsso --default
```

- To sync default profile only, do:
```commandline
yawsso --default-only
```

- To sync for selected named profile, do:
```commandline
yawsso -p dev
```

- To sync for multiple selected named profiles, do:
```commandline
yawsso -p dev prod
```

- To sync for default profile as well as multiple selected named profiles, do:
```commandline
yawsso --default -p dev prod
```

- To sync for all named profiles start with prefix pattern `lab*`, do:
```
(zsh)
yawsso -p 'lab*'

(bash)
yawsso -p lab*
```

- To sync for all named profiles start with prefix pattern `lab*` as well as `dev` and `prod`, do:
```
yawsso -p 'lab*' dev prod
```

- Use `-e` flag if you want a temporary copy-paste-able time-gated access token for an instance or external machine. It use `default` profile if no additional arguments pass. The main use case is for those who use `default` profile, and would like to PIPE like this `aws sso login && yawsso -e | pbcopy`. Otherwise for named profile, do `yawsso -e -p dev`.

    > PLEASE USE THIS FEATURE WITH CARE SINCE **ENVIRONMENT VARIABLES USED ON SHARED SYSTEMS CAN GIVE UNAUTHORIZED ACCESS TO PRIVATE RESOURCES**:

```
yawsso -e
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
```

- You can also use `yawsso` subcommand `login` to SSO login then sync all in one go:
```commandline
yawsso login -h
yawsso login
yawsso login -e
yawsso login --this
yawsso login --profile dev
yawsso login --profile dev --this
```

- Print help to see other options:
```commandline
yawsso -h
```

- Then, continue per normal with your daily tools. i.e. 
    - `cdk deploy ...`
    - `terraform ...`
    - `cw ls -p dev groups`
    - `awsbw -L -P dev` 

## Develop

- Create virtual environment, activate it and then:

```
make install
make test
python -m yawsso --trace version
```

- Create issue or pull request welcome

## License

MIT License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
