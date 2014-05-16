
# adjust as necessary
INC=-I/usr/include/libnetfilter_queue-1.0.2 -I/usr/include/libnfnetlink-1.0.1
LIB=-lnetfilter_queue -lnfnetlink -lpthread -lcap

CXX=c++
CXXFLAGS=-c -Wall -O2 -DUSE_NETFILTERQUEUE -DUSE_CAPS -ansi

all: loaded

clean:
	rm -rf *.o

loaded: packet.o misc.o main.o strategy.o job.o config.o
	$(CXX) packet.o misc.o main.o strategy.o job.o config.o\
	       $(LIB) -o loaded

config.o: config.cc
	$(CXX) $(INC) $(CXXFLAGS) config.cc

job.o: job.cc
	$(CXX) $(INC) $(CXXFLAGS) job.cc

strategy.o: strategy.cc
	$(CXX) $(INC) $(CXXFLAGS) strategy.cc

packet.o: packet.cc
	$(CXX) $(INC) $(CXXFLAGS) packet.cc

main.o: main.cc
	$(CXX) $(INC) $(CXXFLAGS) main.cc

misc.o: misc.cc
	$(CXX) $(INC) $(CXXFLAGS) misc.cc


