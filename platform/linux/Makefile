bin_dir := ../../bin/platform/linux

default: $(bin_dir)/recall.o $(bin_dir)/crypto.o $(bin_dir)/runtime.o $(bin_dir)/intercepts.o ../../include/*.h ../../src/*.o
	$(CXX) -L../../common_deps/wasm-micro-runtime/product-mini/platforms/linux/build/ -g ../../bin/src/*.o $(bin_dir)/*.o  -o ../../bin/nih -lleveldb -lmbedcrypto -lvmlib -lcjson -pthread -lmicrohttpd

$(bin_dir)/%.o: %.cpp ../../include/*.h
	$(CXX) -I../../common_deps/wasm-micro-runtime/core/iwasm/include/  -g -c $< -o $@