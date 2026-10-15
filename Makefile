PYTHON ?= python3
VALUES ?= values-global.yaml
OUTPUT ?= output/rendered.yaml
.PHONY: test lint render demo-preflight install-addon demo-provision bind-volumes demo-status
render:
	$(PYTHON) scripts/addon.py render --values $(VALUES) --output $(OUTPUT)
demo-preflight:
	$(PYTHON) scripts/addon.py preflight --values $(VALUES)
install-addon:
	$(PYTHON) scripts/addon.py install-addon --values $(VALUES)
demo-provision:
	$(PYTHON) scripts/addon.py demo-provision --values $(VALUES)
bind-volumes:
	$(PYTHON) scripts/addon.py bind-volumes --values $(VALUES)
demo-status:
	$(PYTHON) scripts/addon.py status --values $(VALUES)
test:
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) -m unittest discover -s components/confidential-volume-contract
	$(PYTHON) -m unittest discover -s components/confidential-volume-controller
lint:
	$(PYTHON) scripts/addon.py validate --values $(VALUES)
	git diff --check

render-gitops:
	$(PYTHON) scripts/addon.py render-gitops --values $(VALUES) --output $(OUTPUT)
enable-gitops:
	$(PYTHON) scripts/addon.py enable-gitops --values $(VALUES)

demo-chat:
	$(PYTHON) scripts/addon.py demo-chat --values $(VALUES)

include make/quickstart.mk

.PHONY: release-controller-image release-controller-install release-controller-start release-controller-status
release-controller-image:
	$(PYTHON) scripts/release-controller.py image --values $(VALUES)
release-controller-install:
	$(PYTHON) scripts/release-controller.py install --values $(VALUES)
release-controller-start:
	$(PYTHON) scripts/release-controller.py start --values $(VALUES)
release-controller-status:
	$(PYTHON) scripts/release-controller.py status --values $(VALUES)
