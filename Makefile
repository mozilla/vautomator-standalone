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

.PHONY: clean
clean:
	rm -rf results
