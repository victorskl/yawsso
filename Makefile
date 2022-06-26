install:
	@pip install '.[dev,test]' .
	@pre-commit install

check:
	@trufflehog --debug --only-verified git file://./ --since-commit main --branch HEAD --fail
	@pre-commit run --all-files

test:
	@py.test

unit:
	@python -m unittest

coverage:
	@coverage run --source=yawsso -m pytest --cov-report xml tests/

coveralls: coverage
	@coveralls

tox:
	@tox -vv

nose:
	@nose2 -vv

tf:
	@AWS_PROFILE=dev terraform refresh

smoke:
	@terraform plan
	@cdk synth --app "python cdk.py" --profile dev
	@cw ls -p dev groups

.PHONY: doc
doc:
	@py.test --cov-report html:local/coverage --cov=yawsso tests/
	@py.test --cov-report xml:local/coverage.xml --cov=yawsso tests/

clean:
	@rm -rf build/
	@rm -rf yawsso.egg-info/

.PHONY: dist
dist: clean
	@python3 -m build

# Usage: make ver version=0.1.0
ver: dist/yawsso-$(version).tar.gz
	@echo $(version)

testpypi: dist/yawsso-$(version).tar.gz
	@python3 -m twine upload --repository testpypi --sign dist/yawsso-$(version).*
	@python3 -m twine upload --repository testpypi --sign dist/yawsso-$(version)-*

pypi: dist/yawsso-$(version).tar.gz
	@python3 -m twine upload --sign dist/yawsso-$(version).*
	@python3 -m twine upload --sign dist/yawsso-$(version)-*
