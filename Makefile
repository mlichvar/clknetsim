CFLAGS += -O2 -Wall -g -fPIC
CXXFLAGS += $(CFLAGS)
CPPFLAGS += $(sysflags)

all: clknetsim.so clknetsim

sysflags := $(shell echo -e '\x23include <sys/time.h>' | $(CC) -x c -E - | \
	    grep -q __timezone_ptr_t || echo -DGETTIMEOFDAY_VOID)
sysflags += $(shell echo -e '\x23include <linux/net_tstamp.h>' | $(CC) -x c -E - | \
	    grep -q '[^_]SOF_TIMESTAMPING_OPT_ID ' && echo -DHAVE_SOF_TS_OPT_ID)

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
