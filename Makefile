EMACS ?= emacs
SRC = emcp-util.el emcp-curl.el emcp-oauth.el emcp.el

.PHONY: all compile test unit integration clean

all: compile test

compile:
	$(EMACS) -Q --batch -L . \
	  --eval '(setq byte-compile-error-on-warn t)' \
	  -f batch-byte-compile $(SRC)

unit:
	$(EMACS) -Q --batch -L . -L tests \
	  -l tests/emcp-test.el \
	  -f ert-run-tests-batch-and-exit

integration:
	$(EMACS) -Q --batch -L . -L tests \
	  -l tests/emcp-integration-test.el \
	  -f ert-run-tests-batch-and-exit

test:
	$(EMACS) -Q --batch -L . -L tests \
	  -l tests/emcp-test.el \
	  -l tests/emcp-integration-test.el \
	  -f ert-run-tests-batch-and-exit

clean:
	rm -f *.elc tests/*.elc
