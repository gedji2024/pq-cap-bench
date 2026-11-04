UV ?= uv
export OQS_INSTALL_PATH := $(CURDIR)/vendor/liboqs-install
RUN := env -u VIRTUAL_ENV $(UV) run --frozen

.PHONY: all liboqs sync bench env model figures report test cov clean

all: bench model report

liboqs: vendor/liboqs-build-info.json
vendor/liboqs-build-info.json:
	./scripts/build_liboqs.sh

sync:
	env -u VIRTUAL_ENV $(UV) sync --frozen

# Host benchmark (~1 h on Apple M5; dominated by SLH-DSA-128s signing and XMSS keygen).
bench: liboqs sync
	$(RUN) pqcap bench

env: liboqs sync
	$(RUN) pqcap env

model: sync
	$(RUN) pqcap model

figures: sync
	$(RUN) pqcap figures

report: model figures
	$(RUN) pqcap report

test: sync
	$(RUN) pytest

cov: sync
	$(RUN) pytest --cov --cov-report=term-missing

clean:
	rm -rf results/model_* figures/* REPORT.md .pytest_cache .coverage
