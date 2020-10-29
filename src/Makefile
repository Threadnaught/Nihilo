bin_dir = ../bin/src

src: $(bin_dir)/entry.o $(bin_dir)/util.o $(bin_dir)/compute.o $(bin_dir)/talk.o $(bin_dir)/proto.o

$(bin_dir)/%.o: %.cpp ../include/*.h
	$(CXX) -g -c $< -o $@