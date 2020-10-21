.PHONY: linux srcs default_proto
linux: srcs default_proto
	$(MAKE) -C platform/linux/

srcs:
	$(MAKE) -C src/

default_proto:
	$(MAKE) -C machine_prototypes