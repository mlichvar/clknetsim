CC=gcc
CXX=g++
CFLAGS=-O2 -Wall -g
CXXFLAGS=$(CFLAGS)

all: clknetsim.so clknetsim

serverobjs = $(patsubst %.cc,%.o,$(wildcard *.cc))

clknetsim.so: client.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $^ $(LDFLAGS) -ldl -lm

clknetsim: $(serverobjs)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf server *.so *.o core.* .deps

.deps:
	@mkdir .deps

.deps/%.d: %.cc .deps
	@$(CXX) -MM $(CPPFLAGS) -MT '$(<:%.cc=%.o) $@' $< -o $@

-include $(serverobjs:%.o=.deps/%.d)
