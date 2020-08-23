.PHONY: src
src: entry.o util.o

entry.o: entry.cpp ../include/*.h
	g++ -c entry.cpp

util.o: util.cpp ../include/*.h
	g++ -c util.cpp