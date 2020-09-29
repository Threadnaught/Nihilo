default: recall.o crypto.o runtime.o intercepts.o ../../include/*.h ../../src/*.o
	g++ -L../../common_deps/wasm-micro-runtime/product-mini/platforms/linux/build/ -g ../../src/*.o *.o  -o ../../bin/nih -lleveldb -lmbedcrypto -lvmlib -pthread

recall.o: recall.cpp ../../include/*.h
	g++ -g -c recall.cpp

crypto.o: crypto.cpp ../../include/*.h
	g++ -g -c crypto.cpp

runtime.o: runtime.cpp ../../include/*.h
	g++ -I../../common_deps/wasm-micro-runtime/core/iwasm/include/ -g -c runtime.cpp

intercepts.o: intercepts.cpp ../../include/*.h
	g++ -I../../common_deps/wasm-micro-runtime/core/iwasm/include/ -g -c intercepts.cpp