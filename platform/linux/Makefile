default: *.o ../../include/*.h ../../src/*.o
	g++ ../../src/*.o *.o  -o ../../bin/nih -lleveldb -lmbedcrypto

recall.o: recall.cpp ../../include/*.h
	g++ -c recall.cpp

crypto.o: crypto.cpp ../../include/*.h
	g++ -c crypto.cpp