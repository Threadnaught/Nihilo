.PHONY: src
src: entry.o util.o compute.o talk.o

entry.o: entry.cpp ../include/*.h
	g++ -g -c entry.cpp

util.o: util.cpp ../include/*.h
	g++ -g -c util.cpp

compute.o: compute.cpp ../include/*.h
	g++ -g -c compute.cpp

talk.o: talk.cpp ../include/*.h
	g++ -g -c talk.cpp