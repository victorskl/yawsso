# yawsso

[![Pull Request Build Status](https://github.com/victorskl/yawsso/workflows/Pull%20Request%20Build/badge.svg)](https://github.com/victorskl/yawsso/actions) [![Build Status](https://travis-ci.org/victorskl/yawsso.svg?branch=master)](https://travis-ci.org/victorskl/yawsso) [![codecov.io](https://codecov.io/gh/victorskl/yawsso/coverage.svg?branch=master)](https://codecov.io/gh/victorskl/yawsso?branch=master) [![Coverage Status](https://coveralls.io/repos/github/victorskl/yawsso/badge.svg?branch=master)](https://coveralls.io/github/victorskl/yawsso?branch=master) [![Codacy Badge](https://api.codacy.com/project/badge/Grade/e02d74942ed143a381603cd60ba4f64b)](https://app.codacy.com/manual/victorskl/yawsso?utm_source=github.com&utm_medium=referral&utm_content=victorskl/yawsso&utm_campaign=Badge_Grade_Dashboard) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/victorskl/yawsso.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/victorskl/yawsso/context:python) [![Total alerts](https://img.shields.io/lgtm/alerts/g/victorskl/yawsso.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/victorskl/yawsso/alerts/)

Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials.

## Do I need it?

- See https://github.com/victorskl/yawsso/wiki

## Prerequisite

- Required `Python >= 3.6`
- Required [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- Assume you have already setup [AWS SSO](https://aws.amazon.com/single-sign-on/) for your organization

## Main Use Case

- Install [latest from PyPI](https://pypi.org/project/yawsso/) like so:
```commandline
pip install yawsso
```

- Do your per normal SSO login and, have at least one active SSO session cache:
```commandline
aws sso login --profile dev
```

- To sync for all named profiles in config (i.e. _lazy consensus_), then just:
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

- To sync for all named profiles start with `lab*` as well as `dev` and `prod`, do:
```
yawsso -p 'lab*' dev prod
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

## Additional Use Case

### Export Tokens

- Use `-e` flag if you want a temporary copy-paste-able time-gated access token for an instance or external machine.

> 🤚 PLEASE USE THIS FEATURE WITH CARE SINCE **ENVIRONMENT VARIABLES USED ON SHARED SYSTEMS CAN GIVE UNAUTHORIZED ACCESS TO PRIVATE RESOURCES**:

- Please note that, it uses `default` profile if no additional arguments pass.
```
yawsso -e
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
```

- This use case is especially tailored for those who use `default` profile and, who would like to PIPE commands as follows.
```
aws sso login && yawsso -e | pbcopy
```

- Otherwise for a named profile, do:
```commandline
yawsso -p dev -e
```

- If you have [`pyperclip`](https://github.com/asweigart/pyperclip) package installed, `yawsso` will copy access tokens to your clipboard instead.
```
yawsso -e
Credentials copied to your clipboard for profile 'default'
```

- You may `pip install pyperclip` or, together with `yawsso` as follows.
```
pip install 'yawsso[all]'
```

### Login

- You can also use `yawsso` subcommand `login` to SSO login then sync all in one go.

> 🙋‍♂️ NOTE: It uses `default` profile if optional argument `--profile` is absent

```commandline
yawsso login -h
yawsso login
```

- Otherwise you can pass the _login profile_ as follows:
```
yawsso login --profile dev
```

- Due to _lazy consensus_ design, `yawsso` will sync all named profiles once SSO login has succeeded. If you'd like to sync only upto this _login profile_ then use `--this` flag to limit as follows.

> 👉 Login using default profile and sync only upto **this** default profile
```
yawsso login --this
```

> 👉 Login using named profile dev and sync only upto **this** dev profile
```
yawsso login --profile dev --this
```

#### Login then Export token

- Exporting access token also support with login subcommand as follows: 

> 👉 Login using default profile, sync only upto **this** default profile and, print access token
```
yawsso login -e
```

> 👉 Login using named profile dev, sync only upto **this** dev profile and, print access token
```
yawsso login --profile dev -e
```

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
