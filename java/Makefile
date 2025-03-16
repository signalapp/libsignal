#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

DOCKER ?= docker

.PHONY: docker java_build publish_java

default: java_build

DOCKER_IMAGE := libsignal-builder
DOCKER_TTY_FLAG := $$(test -t 0 && echo -it)
CROSS_COMPILE_SERVER ?= -PcrossCompileServer

docker_image:
	cd .. && $(DOCKER) build --build-arg UID=$$(id -u) --build-arg GID=$$(id -g) -t $(DOCKER_IMAGE) -f java/Dockerfile .

java_build: DOCKER_EXTRA=$(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
java_build: docker_image
	$(DOCKER) run $(DOCKER_TTY_FLAG) --init --rm --user $$(id -u):$$(id -g) \
		--env LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS \
        -v `cd .. && pwd`/:/home/libsignal/src $(DOCKER_EXTRA) $(DOCKER_IMAGE) \
        sh -c "cd src/java; ./gradlew build $(CROSS_COMPILE_SERVER)"

publish_java: DOCKER_EXTRA = $(shell [ -L build ] && P=$$(readlink build) && echo -v $$P/:$$P )
publish_java: docker_image
	$(DOCKER) run --rm --user $$(id -u):$$(id -g) \
		-v `cd .. && pwd`/:/home/libsignal/src $(DOCKER_EXTRA) \
		-e ORG_GRADLE_PROJECT_sonatypeUsername \
		-e ORG_GRADLE_PROJECT_sonatypePassword \
		-e ORG_GRADLE_PROJECT_signingKeyId \
		-e ORG_GRADLE_PROJECT_signingPassword \
		-e ORG_GRADLE_PROJECT_signingKey \
		$(DOCKER_IMAGE) \
		sh -c "cd src/java; ./gradlew publish closeAndReleaseStagingRepositories $(CROSS_COMPILE_SERVER)"

# We could run these through Docker, but they would have the same result anyway.

clean:
	./gradlew clean

format_java:
	./gradlew spotlessApply
