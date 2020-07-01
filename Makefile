install:
	@pip install '.[dev,test]' .

test:
	@py.test

unit:
	@python -m unittest

coverage:
	@coverage run --source=yawsso -m pytest tests/

tox:
	@tox -vv

tf:
	@AWS_PROFILE=dev terraform refresh

.PHONY: doc
doc:
	@py.test --cov-report html:local/coverage --cov=yawsso tests/
	@py.test --cov-report xml:local/coverage.xml --cov=yawsso tests/

.PHONY: dist
dist:
	@python setup.py sdist bdist_wheel

# Usage: make ver version=0.1.0
ver: dist/yawsso-$(version).tar.gz
	@echo $(version)

testpypi: dist/yawsso-$(version).tar.gz
	@twine upload --repository testpypi --sign dist/yawsso-$(version)*

pypi: dist/yawsso-$(version).tar.gz
	@twine upload --sign dist/yawsso-$(version)*
