default: ../../bin/platform/linux/recall.o ../../bin/platform/linux/crypto.o ../../bin/platform/linux/runtime.o ../../bin/platform/linux/intercepts.o ../../include/*.h ../../src/*.o
	$(CXX) -L../../common_deps/wasm-micro-runtime/product-mini/platforms/linux/build/ -g ../../bin/src/*.o ../../bin/platform/linux/*.o  -o ../../bin/nih -lleveldb -lmbedcrypto -lvmlib -lcjson -pthread -lmicrohttpd

../../bin/platform/linux/%.o: %.cpp ../../include/*.h
	$(CXX) -I../../common_deps/wasm-micro-runtime/core/iwasm/include/  -g -c $< -o $@