#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

DOCKER ?= docker

.PHONY: docker java_build java_test publish_java

default: java_build

DOCKER_IMAGE := libsignal-builder
DOCKER_TTY_FLAG := $$(test -t 0 && echo -it)

docker_image:
	cd .. && $(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t $(DOCKER_IMAGE) -f java/Dockerfile .

java_build: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
java_build: docker_image
	$(DOCKER) run $(DOCKER_TTY_FLAG) --init --rm --user $$(id -u):$$(id -g) \
	  -v `cd .. && pwd`/:/home/libsignal/src $(DOCKER_EXTRA) $(DOCKER_IMAGE) \
		sh -c "cd src/java; ./gradlew build"

java_test: java_build
	$(DOCKER) run $(DOCKER_TTY_FLAG) --init --rm --user $$(id -u):$$(id -g) \
	  -v `cd .. && pwd`/:/home/libsignal/src $(DOCKER_EXTRA) $(DOCKER_IMAGE) \
		sh -c "cd src/java; ./gradlew test"

SONATYPE_USERNAME     ?=
SONATYPE_PASSWORD     ?=
KEYRING_FILE          ?=
SIGNING_KEY           ?=
SIGNING_KEY_PASSSWORD ?=

publish_java: DOCKER_EXTRA = $(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
publish_java: KEYRING_VOLUME := $(dir $(KEYRING_FILE))
publish_java: KEYRING_FILE_ROOT := $(notdir $(KEYRING_FILE))
publish_java: docker_image
	@[ -n "$(SONATYPE_USERNAME)" ]    || ( echo "SONATYPE_USERNAME is not set" && false )
	@[ -n "$(SONATYPE_PASSWORD)" ]    || ( echo "SONATYPE_PASSWORD is not set" && false )
	@[ -n "$(KEYRING_FILE)" ]         || ( echo "KEYRING_FILE is not set" && false )
	@[ -n "$(SIGNING_KEY)" ]          || ( echo "SIGNING_KEY is not set" && false )
	@[ -n "$(SIGNING_KEY_PASSWORD)" ] || ( echo "SIGNING_KEY_PASSWORD is not set" && false )
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
		-v `cd .. && pwd`/:/home/libsignal/src $(DOCKER_EXTRA) \
		-v $(KEYRING_VOLUME):/home/libsignal/keyring \
		$(DOCKER_IMAGE) \
		sh -c "cd src/java; ./gradlew clean publish \
			-PsonatypeUsername='$(SONATYPE_USERNAME)' \
			-PsonatypePassword='$(SONATYPE_PASSWORD)' \
			-Psigning.secretKeyRingFile='/home/libsignal/keyring/$(KEYRING_FILE_ROOT)' \
			-Psigning.keyId='$(SIGNING_KEY)' \
			-Psigning.password='$(SIGNING_KEY_PASSWORD)'"
