# yawsso

[![DOI](https://zenodo.org/badge/267410733.svg)](https://zenodo.org/badge/latestdoi/267410733)
[![Pull Request Build Status](https://github.com/victorskl/yawsso/workflows/Pull%20Request%20Build/badge.svg)](https://github.com/victorskl/yawsso/actions/workflows/prbuild.yml) 
[![CodeQL](https://github.com/victorskl/yawsso/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/victorskl/yawsso/actions/workflows/codeql-analysis.yml) 
[![codecov.io](https://codecov.io/gh/victorskl/yawsso/coverage.svg?branch=main)](https://codecov.io/gh/victorskl/yawsso?branch=main)
[![coveralls.io](https://coveralls.io/repos/github/victorskl/yawsso/badge.svg?branch=main)](https://coveralls.io/github/victorskl/yawsso?branch=main)
[![codeclimate - Test Coverage](https://api.codeclimate.com/v1/badges/44dd1cbae44465118742/test_coverage)](https://codeclimate.com/github/victorskl/yawsso/test_coverage)
[![codeclimate - Maintainability](https://api.codeclimate.com/v1/badges/44dd1cbae44465118742/maintainability)](https://codeclimate.com/github/victorskl/yawsso/maintainability)
[![snyk](https://snyk.io/advisor/python/yawsso/badge.svg)](https://snyk.io/advisor/python/yawsso) 
[![kandi](https://img.shields.io/badge/kandi-X--Ray%20Report-ff69b4)](https://kandi.openweaver.com/python/victorskl/yawsso) 
[![PyPI - Downloads](https://img.shields.io/pypi/dm/yawsso?style=flat)](https://pypistats.org/packages/yawsso) 
[![PyPI](https://img.shields.io/pypi/v/yawsso?style=flat)](https://pypi.org/project/yawsso)
[![PyPI - License](https://img.shields.io/pypi/l/yawsso?style=flat)](https://opensource.org/licenses/MIT)


Yet Another AWS SSO - sync up AWS CLI v2 SSO login session to legacy CLI v1 credentials.

> See also [Release v1.0.0 Notes](https://github.com/victorskl/yawsso/wiki#release-100-notes)

## Prerequisite

- Required `Python >= 3.7`
- Required [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html)
- Assume you have already setup [AWS SSO](https://aws.amazon.com/single-sign-on/) for your organization

## Main Use Case

- Install [latest from PyPI](https://pypi.org/project/yawsso/#history) like so:
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
    - `terraform apply ...`
    - `cw ls groups`
    - `awsbw -L -P dev`
    - `sqsmover -s main-dlq -d main-queue`
    - `ecs-cli ps --cluster my-cluster`
    - `awscurl -H "Accept: application/json" --profile dev --region ap-southeast-2 "https://api..."`

## Additional Use Cases

### Rename Profile on Sync

- Say, you have the following profile in your `$HOME/.aws/config`:
```
[profile dev]
sso_start_url = https://myorg.awsapps.com/start
sso_region = ap-southeast-2
sso_account_id = 123456789012
sso_role_name = AdministratorAccess
region = ap-southeast-2
output = json
cli_pager =
```

- You want to populate access token as, say, profile name `foo` in `$HOME/.aws/credentials`:
```
[foo]
region = ap-southeast-2
aws_access_key_id = XXX
aws_secret_access_key = XXX
aws_session_token = XXX
...
```

- Do like so:
```
yawsso -p dev:foo
```

- Then, you can `export AWS_PROFILE=foo` and use `foo` profile!

### Export Tokens

> PLEASE USE THIS FEATURE WITH CARE SINCE **ENVIRONMENT VARIABLES USED ON SHARED SYSTEMS CAN GIVE UNAUTHORIZED ACCESS TO PRIVATE RESOURCES**.

> 🤚 START FROM VERSION `1.0.0`, `yawsso -e` EXPORT TOKENS IN **ROT13** ENCODED STRING.

- Use `-e` flag if you want a temporary copy-paste-able time-gated access token for an instance or external machine.

- Please note that, it uses `default` profile if no additional arguments pass.
```
yawsso -e | yawsso decrypt
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export AWS_SESSION_TOKEN=xxx
```

- This use case is especially tailored for those who use `default` profile and, who would like to PIPE commands as follows.
```
aws sso login && yawsso -e | yawsso decrypt | pbcopy
```

- Otherwise, for a named profile, do:
```
yawsso -p dev -e | yawsso decrypt
```

- Or, right away export credentials into the current shell environment variables, do:
```
yawsso -p dev -e | yawsso decrypt | source /dev/stdin
```

> Note: ☝️ are mutually exclusive with the following 👇 auto copy into your clipboard. **Choose one, a must!** 

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

> 🙋‍♂️ NOTE: It uses `default` profile or `AWS_PROFILE` environment variable if optional argument `--profile` is absent

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

> 👉 Login using named profile dev and sync as foo. See above for more details on renaming, limited to one profile. 
```
yawsso login --profile dev:foo
```

#### Login then Export token

- Exporting access token also support with login subcommand as follows: 

> 👉 Login using default profile, sync only upto **this** default profile and, print access token
```
yawsso login -e | yawsso decrypt
```

> 👉 Login using named profile dev, sync only upto **this** dev profile and, print access token
```
yawsso login --profile dev -e | yawsso decrypt
```

### Auto Login then Sync

- Like `login`, you may use `yawsso` subcommand `auto` to SSO login then sync all in one go.
- It will check if SSO session has expired and, if so, `yawsso` will attempt to auto login again.

```
yawsso auto -h

(either)
yawsso auto --profile dev

(or)
export AWS_PROFILE=dev
yawsso auto
```

### Set Region

- You can also set region from the config file to the shared credentials file
- Do like so:

```
yawsso -r -p dev
```

```
yawsso -r -p dev:foo
```

```
yawsso -r auto --profile dev
```

### Encryption

`yawsso` can encrypt and decrypt some arbitrary string from `stdin` using [ROT13](https://en.wikipedia.org/wiki/ROT13) (_a simple letter substitution cipher_) as follows.

```
echo 'Hello this is a test' | yawsso encrypt
Uryyb guvf vf n grfg

echo 'Uryyb guvf vf n grfg' | yawsso decrypt
Hello this is a test

(or Pipe through some text corpus)
cat test.txt | yawsso encrypt

(or on Windows)
type test.txt | yawsso encrypt
```

This is the same as using trivial Unix `tr` command as follows.

```
echo 'Hello this is a test' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
Uryyb guvf vf n grfg

echo 'Uryyb guvf vf n grfg' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
Hello this is a test
```

Hence, you could also decode `yawsso` exported tokens using `tr` command, like so.

```
yawsso -p dev -e | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## Develop

- Create virtual environment, activate it and then:

```
make install
make test
python -m yawsso --trace version
```

(Windows)

```
python -m venv venv
.\venv\Scripts\activate
pip install ".[dev,test]" .
pytest
python -m yawsso --trace version
```

- Create issue or pull request welcome

## License

MIT License

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
