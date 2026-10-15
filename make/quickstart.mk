# Operator-driven release stages. No timestamp-based recipes for external state.
RUN ?=
QS_STAGES := tools dependencies preflight bootstrap build push install model volumes measure enroll deploy test-first test-reopen report chat status
.PHONY: $(addprefix qs-,$(QS_STAGES)) quickstart-all quickstart-resume
$(addprefix qs-,$(QS_STAGES)):
	$(PYTHON) scripts/quickstart.py $(@:qs-%=%) --values "$(VALUES)" --run "$(RUN)"
quickstart-all quickstart-resume:
	$(PYTHON) scripts/quickstart.py all --values "$(VALUES)" --run "$(RUN)"
