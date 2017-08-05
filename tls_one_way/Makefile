# ©.

CROSS        =
export CC    = $(CROSS)gcc
export LD    = $(CROSS)ld
export AR    = $(CROSS)ar
export STRIP = $(CROSS)strip

CC_FLAGS = -Wall -O2
LD_FLAGS =

INCLUDE_PATH =
LIBRARY_PATH =

LIBRARY_FILE = -lssl -lcrypto

SOURCE_FILE = $(wildcard *.c)

TLS_ONE_WAY_CLIENT_OBJECT_FILE = tls_one_way_client.o
TLS_ONE_WAY_CLIENT_TARGET_FILE = tls_one_way_client

TLS_ONE_WAY_SERVER_OBJECT_FILE = tls_one_way_server.o
TLS_ONE_WAY_SERVER_TARGET_FILE = tls_one_way_server


all : $(TLS_ONE_WAY_CLIENT_TARGET_FILE) $(TLS_ONE_WAY_SERVER_TARGET_FILE)


$(TLS_ONE_WAY_CLIENT_TARGET_FILE) : $(TLS_ONE_WAY_CLIENT_OBJECT_FILE)
	$(CC) $(LD_FLAGS) $(LIBRARY_PATH) $^ $(LIBRARY_FILE) -o $@
	$(STRIP) $@

$(TLS_ONE_WAY_SERVER_TARGET_FILE) : $(TLS_ONE_WAY_SERVER_OBJECT_FILE)
	$(CC) $(LD_FLAGS) $(LIBRARY_PATH) $^ $(LIBRARY_FILE) -o $@
	$(STRIP) $@

%.o : %.c
	$(CC) $(CC_FLAGS) $(INCLUDE_PATH) -c $< -o $@

%.d : %.c
	@set -e; rm -f $@; \
	$(CC) $(CC_FLAGS) $(INCLUDE_PATH) -MM $< > $@.$$$$; 2>/dev/null; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(SOURCE_FILE:.c=.d)

clean :
	rm -f *.d *.d* *.o $(TLS_ONE_WAY_CLIENT_TARGET_FILE) $(TLS_ONE_WAY_SERVER_TARGET_FILE)
