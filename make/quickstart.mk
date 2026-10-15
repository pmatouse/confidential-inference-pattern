# Shared administrator foundation, followed by manual or controller-owned release.
RUN ?=
QS_FOUNDATION_STAGES := tools dependencies preflight integrations bootstrap build push install
QS_RELEASE_STAGES := model volumes measure enroll deploy test-first test-reopen report
QS_STAGES := $(QS_FOUNDATION_STAGES) $(QS_RELEASE_STAGES) chat status
.PHONY: $(addprefix qs-,$(QS_STAGES)) quickstart-all quickstart-resume quickstart-foundation controller-demo
$(addprefix qs-,$(QS_STAGES)):
	$(PYTHON) scripts/quickstart.py $(@:qs-%=%) --values "$(VALUES)" --run "$(RUN)"
quickstart-all quickstart-resume:
	$(PYTHON) scripts/quickstart.py all --values "$(VALUES)" --run "$(RUN)"

# Keep prerequisites sequential even with make -j; tools creates the private venv.
quickstart-foundation:
	$(MAKE) qs-tools VALUES="$(VALUES)" RUN="$(RUN)" PYTHON="$(PYTHON)"
	@set -e; for stage in $(filter-out tools,$(QS_FOUNDATION_STAGES)); do \
	  $(MAKE) "qs-$$stage" VALUES="$(VALUES)" RUN="$(RUN)" PYTHON="$${QUICKSTART_CACHE:-$(CURDIR)/.cache/quickstart}/venv/bin/python"; \
	done

# The same foundation is used by both paths. Handover precedes release submission.
controller-demo: quickstart-foundation
	@set -e; for stage in release-controller-image release-controller-install release-controller-start; do \
	  $(MAKE) "$$stage" VALUES="$(VALUES)" RUN="$(RUN)" PYTHON="$${QUICKSTART_CACHE:-$(CURDIR)/.cache/quickstart}/venv/bin/python"; \
	done
