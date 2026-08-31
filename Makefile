.PHONY: check policy dependency-audit rust qualify release-preflight release-package publish

check: policy dependency-audit

policy:
	python3 scripts/check-policy.py --skip-manifest

dependency-audit:
	python3 scripts/dependency_audit.py

rust:
	bash scripts/qualify.sh --lane rust

qualify:
	bash scripts/qualify.sh

release-preflight:
	bash scripts/release_qualify.sh release-preflight

release-package:
	bash scripts/release_qualify.sh package

publish:
	bash scripts/publish_to_github.sh
