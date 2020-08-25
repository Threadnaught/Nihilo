.PHONY: linux srcs
linux: srcs
	$(MAKE) -C platform/linux/

srcs:
	$(MAKE) -C src/