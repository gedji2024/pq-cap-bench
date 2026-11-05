UV ?= uv
export OQS_INSTALL_PATH := $(CURDIR)/vendor/liboqs-install
RUN := env -u VIRTUAL_ENV $(UV) run --frozen

.PHONY: all liboqs sync bench env model figures report test cov clean data formal

all: bench model report

liboqs: vendor/liboqs-build-info.json
vendor/liboqs-build-info.json:
	./scripts/build_liboqs.sh

# Re-fetch the cached USGS series (writes data/*.json + .meta.json with URL, date, SHA-256).
data:
	python3 scripts/fetch_usgs.py 08074000 00065 2017-08-26 2017-08-31

# Tamarin proofs (brew trust tamarin-prover/tap && brew install tamarin-prover/tap/tamarin-prover).
# crisis.spthy needs the `s` heuristic for the inductive counter lemma (default heuristic does not terminate).
formal:
	tamarin-prover --version > formal/proofs/VERSION.txt 2>&1
	cd formal && python3 make_freshness.py crisis.spthy freshness.spthy
	cd formal && ./prove.sh freshness.spthy s 1800 ctr_monotone P4_no_replay P4_injective_agreement
	cd formal && ./prove.sh crisis.spthy s 1800 exec_accept exec_disable exec_revoke P1_confinement \
	  revocation revocation_needs_PA disable_needs_OP
	tamarin-prover --prove formal/delegation.spthy > formal/proofs/delegation.txt 2>&1

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
