CFLAGS += -O2 -Wall -g -fPIC
CXXFLAGS += $(CFLAGS)
CPPFLAGS += $(apiflags)

all: clknetsim.so clknetsim

apiflags := $(shell grep -q __timezone_ptr_t /usr/include/sys/time.h || echo -DGETTIMEOFDAY_VOID)

clientobjs = client.o
serverobjs = $(patsubst %.cc,%.o,$(wildcard *.cc))

clknetsim.so: $(clientobjs)
	$(CC) $(CFLAGS) -shared -o $@ $^ $(LDFLAGS) -ldl -lm

clknetsim: $(serverobjs)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf clknetsim *.so *.o core.* .deps

.deps:
	@mkdir .deps

.deps/%.d: %.c .deps
	@$(CC) -MM $(CPPFLAGS) -MT '$(<:%.c=%.o) $@' $< -o $@

.deps/%.D: %.cc .deps
	@$(CXX) -MM $(CPPFLAGS) -MT '$(<:%.cc=%.o) $@' $< -o $@

-include $(clientobjs:%.o=.deps/%.d) $(serverobjs:%.o=.deps/%.D)
