# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.

SYSTEM_DIR        ?= /home/vagrant/test-secrets
BOOTSTRAP_MINUTES ?= 5
ROOT_CA_DIR       ?= /home/vagrant/test-secrets
KEYSTORE_PASS     ?= changeit
TRUSTSTORE_PASS   ?= changeit

all : bootstrap-test-certs bootstrap-test-certs-clean create-empty-keystore
.PHONY : all

bootstrap-test-certs:
	./scripts/generate-bootstrap-cert.sh \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)


bootstrap-test-certs-clean:
	./scripts/generate-bootstrap-cert.sh --clean \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)

create-empty-keystore:
	./scripts/generate-bootstrap-cert.sh --clean --empty-keystore \
	  $(SYSTEM_DIR) \
	  $(BOOTSTRAP_MINUTES) \
	  $(ROOT_CA_DIR) \
	  $(KEYSTORE_PASS) \
	  $(TRUSTSTORE_PASS)
