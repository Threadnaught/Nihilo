.PHONY: linux srcs wasm
linux: srcs wasm
	$(MAKE) -C platform/linux/

srcs:
	$(MAKE) -C src/

wasm:
	$(MAKE) -C wasm_develop/