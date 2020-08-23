default: *.o ../../include/*.h ../../src/*.o
	g++ ../../src/*.o *.o  -o ../../bin/nih -lleveldb -lmbedcrypto

recall.o: recall.cpp ../../include/*.h
	g++ -c recall.cpp

crypt.o: crypt.cpp ../../include/*.h
	g++ -c crypt.cpp