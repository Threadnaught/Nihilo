default:
	/opt/wasi-sdk/bin/clang	 \
		--target=wasm32 -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
		--sysroot=../common_deps/wasm-micro-runtime/wamr-sdk/app/libc-builtin-sysroot \
		-Wl,--allow-undefined-file=../common_deps/wasm-micro-runtime/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \
		-Wl,--no-threads,--strip-all,--no-entry -nostdlib \
		-Wl,--export-all \
		-o test.wasm main.c