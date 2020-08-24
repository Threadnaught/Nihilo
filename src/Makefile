.PHONY: src
src: entry.o util.o compute.o talk.o

entry.o: entry.cpp ../include/*.h
	g++ -c entry.cpp

util.o: util.cpp ../include/*.h
	g++ -c util.cpp

compute.o: compute.cpp ../include/*.h
	g++ -c compute.cpp

talk.o: talk.cpp ../include/*.h
	g++ -c talk.cpp