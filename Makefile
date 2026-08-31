.PHONY: check qualify test fmt publish

check:
	python3 scripts/check-policy.py

fmt:
	cargo fmt --all --check

test:
	cargo test --workspace

qualify:
	bash scripts/qualify.sh

publish:
	bash scripts/publish_to_github.sh
