# Operator-driven release stages. No timestamp-based recipes for external state.
RUN ?=
QS_STAGES := tools dependencies preflight integrations bootstrap build push install model volumes measure enroll deploy test-first test-reopen report chat status
.PHONY: $(addprefix qs-,$(QS_STAGES)) quickstart-all quickstart-resume
$(addprefix qs-,$(QS_STAGES)):
	$(PYTHON) scripts/quickstart.py $(@:qs-%=%) --values "$(VALUES)" --run "$(RUN)"
quickstart-all quickstart-resume:
	$(PYTHON) scripts/quickstart.py all --values "$(VALUES)" --run "$(RUN)"

# Bootstrap once; all subsequent release stages run only in the controller.
.PHONY: controller-demo
controller-demo:
	$(MAKE) qs-tools VALUES="$(VALUES)" PYTHON="$(PYTHON)"
	@set -e; for stage in qs-dependencies qs-preflight qs-integrations qs-bootstrap qs-build qs-push qs-install release-controller-image release-controller-install release-controller-start; do \
	  $(MAKE) "$$stage" VALUES="$(VALUES)" PYTHON="$${QUICKSTART_CACHE:-$(CURDIR)/.cache/quickstart}/venv/bin/python"; \
	done
