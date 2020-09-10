default:
	WAMR_DIR="../common_deps/wasm-micro-runtime"
	#/opt/wasi-sdk/bin/clang++ main.cpp -nostartfiles -Wl,--no-entry,--export-all-symbols -nostdlib -o test.wasm
	/opt/wasi-sdk/bin/clang	 \
		--target=wasm32 -O0 -z stack-size=4096 -Wl,--initial-memory=65536 \
		--sysroot=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot  \
		-Wl,--no-threads,--strip-all,--no-entry -nostdlib \
		-Wl,--export=calculate \
		-o test.wasm main.c

		#-Wl,--allow-undefined-file=${WAMR_DIR}/wamr-sdk/app/libc-builtin-sysroot/share/defined-symbols.txt \