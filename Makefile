.PHONY: linux
linux: src/*.o
	$(MAKE) -C platform/linux/

src/*.o:
	$(MAKE) -C src/