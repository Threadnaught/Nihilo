SHELL := /bin/bash
CXX := g++
export CXX

.PHONY: linux srcs machine_prototypes
linux: srcs machine_prototypes
	$(MAKE) -C platform/linux/ -e

srcs:
	$(MAKE) -C src/ -e

machine_prototypes:
	$(MAKE) -C machine_prototypes -e

clean:
	find bin | grep \\.o$ | xargs -r rm
	echo bin/nih | xargs -r rm -f
	rm machine_prototypes/bin/*.wasm -f