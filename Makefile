PYTHON ?= python3

.PHONY: audit test verify

audit:
	$(PYTHON) -m auditor inputs/snapshot-one --out outputs/snapshot-one
	$(PYTHON) -m auditor inputs/snapshot-two --out outputs/snapshot-two

test:
	$(PYTHON) -m unittest discover -s tests -t . -v

verify:
	$(PYTHON) tools/verify.py > outputs/verification.txt
