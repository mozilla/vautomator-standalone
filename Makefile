ROOT_DIR	:= $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
TARGET		:= 

all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]^\.PHONY.*].*:' Makefile

.PHONY: build
build: Dockerfile docker-compose.yml
	docker-compose build vautomator

.PHONY: force-build
force-build: Dockerfile docker-compose.yml
	docker-compose build --no-cache vautomator

.PHONY: fullscan
fullscan:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -a $(TARGET)

.PHONY: portscan
portscan:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -p $(TARGET)

.PHONY: nessusscan
nessusscan:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -n $(TARGET)

.PHONY: observatory
observatory:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -o $(TARGET)

.PHONY: tlsobs
tlsobs:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -t $(TARGET)

.PHONY: sshscan
sshscan:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -s $(TARGET)

.PHONY: direnum
direnum:
	docker run -v ${PWD}/results:/app/results -it vautomator:latest ./run.py -d $(TARGET)

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
