default: bin/hello_world.wasm bin/com_example.wasm bin/net_example.wasm bin/http.wasm

bin/%.wasm: %/main.c ../include/api.h
	mkdir -p bin
	cat ../common_deps/wasm-micro-runtime/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt ../include/api-undef.txt > all-undef.txt
	/opt/wasi-sdk/bin/clang \
		--target=wasm32 -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
		--sysroot=../common_deps/wasm-micro-runtime/wamr-sdk/app/libc-builtin-sysroot \
		-Wl,--allow-undefined-file=all-undef.txt \
		-Wl,--no-threads,--strip-all,--no-entry -nostdlib \
		-Wl,--export-all \
		-o $@ $<
	rm all-undef.txt