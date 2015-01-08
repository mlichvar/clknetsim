CC=gcc
CXX=g++
CFLAGS=-O2 -Wall -g -fPIC
CXXFLAGS=$(CFLAGS)

all: clknetsim.so clknetsim

clientobjs = client.o
serverobjs = $(patsubst %.cc,%.o,$(wildcard *.cc))

clknetsim.so: $(clientobjs)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) -ldl -lm

clknetsim: $(serverobjs)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf server *.so *.o core.* .deps

.deps:
	@mkdir .deps

.deps/%.d: %.c .deps
	@$(CC) -MM $(CPPFLAGS) -MT '$(<:%.c=%.o) $@' $< -o $@

.deps/%.D: %.cc .deps
	@$(CXX) -MM $(CPPFLAGS) -MT '$(<:%.cc=%.o) $@' $< -o $@

-include $(clientobjs:%.o=.deps/%.d) $(serverobjs:%.o=.deps/%.D)
