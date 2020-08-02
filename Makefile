msg = @printf '  %-8s %s\n' "$(1)" "$(if $(2), $(notdir $(2)))";

.PHONY: dev
dev:
	$(call msg,INSTALL,pip3 install -e .)
	@sudo su -c "pip3 install -e ."

.PHONY: test
test:
	$(call msg,TEST,pytest)
	@sudo pytest

.PHONY: libbpf
libbpf:
	git submodule update
	$(MAKE) -c pybpf/libbpf -j$(shell nproc)
	sudo su -c "$(MAKE) -c pybpf/libbpf install"
