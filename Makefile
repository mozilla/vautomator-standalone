ROOT_DIR	:= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET		:= 

all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]^\.PHONY.*].*:' Makefile

.PHONY: build
build: Dockerfile docker-compose.yml
	docker-compose build vautomator

.PHONY: scan
scan:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py $(TARGET)

.PHONY: test
test:
	python -m pytest tests/

.PHONY: flake8
flake8:
	flake8 lib/*py
	flake8 tests/*py

.PHONY: test-tox
test-tox:
	tox

.PHONY: clean
clean:
	rm -rf results
	rm -rf .tox
	rm -rf .eggs
	rm -rf .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {}\;
	rm -rf vautomator.egg-info
