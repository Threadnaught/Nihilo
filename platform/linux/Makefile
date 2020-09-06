default: recall.o crypto.o ../../include/*.h ../../src/*.o
	g++ -g ../../src/*.o *.o  -o ../../bin/nih -lleveldb -lmbedcrypto

recall.o: recall.cpp ../../include/*.h
	g++ -g -c recall.cpp

crypto.o: crypto.cpp ../../include/*.h
	g++ -g -c crypto.cpp