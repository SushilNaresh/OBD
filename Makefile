CC = gcc
PKG_CONFIG_PATH ?= /opt/homebrew/Cellar/pjproject/2.17/lib/pkgconfig
OPENSSL_LIB = $(shell brew --prefix openssl@3 2>/dev/null || echo "/usr/lib")/lib

CFLAGS = -Wall -O2 -std=c11 -D_GNU_SOURCE \
         $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags libpjproject 2>/dev/null || echo "-I/usr/local/include")
LDFLAGS = -L$(OPENSSL_LIB) \
          $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs --static libpjproject 2>/dev/null || echo "-L/usr/local/lib -lpjsua -lpjsip-ua -lpjsip-simple -lpjsip -lpjmedia-codec -lpjmedia -lpjmedia-audiodev -lpjnath -lpjlib-util -lpj") \
          -lm -lpthread

TARGET = obd
SRCS = main.c dispatcher.c worker.c sip_engine.c dedup.c udp_report.c obd_logger.c
OBJS = $(SRCS:.c=.o)

# Default build
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -g -o $@ $^ $(LDFLAGS)

%.o: %.c obd.h
	$(CC) $(CFLAGS) -g -c -o $@ $<

# Tune target — override compile-time constants
# Usage: make tune OBD_NUM_WORKERS=800 OBD_CALLS_PER_WORKER=16
tune:
	$(CC) $(CFLAGS) \
		$(if $(OBD_NUM_WORKERS),-DOBD_NUM_WORKERS=$(OBD_NUM_WORKERS)) \
		$(if $(OBD_CALLS_PER_WORKER),-DOBD_CALLS_PER_WORKER=$(OBD_CALLS_PER_WORKER)) \
		$(if $(OBD_DISPATCH_THREADS),-DOBD_DISPATCH_THREADS=$(OBD_DISPATCH_THREADS)) \
		$(if $(OBD_REPORT_THREADS),-DOBD_REPORT_THREADS=$(OBD_REPORT_THREADS)) \
		$(if $(OBD_UDP_LISTEN_PORT),-DOBD_UDP_LISTEN_PORT=$(OBD_UDP_LISTEN_PORT)) \
		$(if $(OBD_SIP_PORT_BASE),-DOBD_SIP_PORT_BASE=$(OBD_SIP_PORT_BASE)) \
		$(if $(OBD_SIP_MUX_PORT),-DOBD_SIP_MUX_PORT=$(OBD_SIP_MUX_PORT)) \
		$(if $(OBD_SIP_T1_MS),-DOBD_SIP_T1_MS=$(OBD_SIP_T1_MS)) \
		$(if $(OBD_DEFAULT_TIMEOUT),-DOBD_DEFAULT_TIMEOUT=$(OBD_DEFAULT_TIMEOUT)) \
		-o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(OBJS)

# Pretty log viewing
logs:
	@echo "Pipe obd output through jq:"
	@echo "  ./obd 10.0.0.20 9100 | jq -r '\"\\(.ts) [\\(.w)] \\(.req // \"-\") \\(.ev)\"'"

.PHONY: all tune clean logs
