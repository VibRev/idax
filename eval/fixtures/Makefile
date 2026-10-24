# Cross-compile the fixtures to stripped ARM64 ELFs (the decompiler tasks
# need the ARM Hex-Rays decompiler), and bnx reuses the same binaries so the two
# suites judge the same ground truth.
CC = aarch64-linux-gnu-gcc
CFLAGS ?= -O1 -fno-inline -s
SRCS := $(wildcard *.c)
BINS := $(SRCS:.c=)
all: $(BINS)
# Without the cross compiler (macOS), copy the binary from bin/, which keeps
# the source it was built from: a stale copy is refused. `make prebuilt`
# refreshes bin/ where the compiler is.
%: %.c
	@if command -v $(CC) >/dev/null 2>&1; then echo "$(CC) $(CFLAGS) -o $@ $<"; $(CC) $(CFLAGS) -o $@ $<; \
	elif cmp -s $< bin/$<; then cp bin/$@ $@; \
	else echo "no $(CC), and bin/$@ is stale against $< (run make prebuilt where it is)" >&2; exit 1; fi
prebuilt: $(BINS)
	mkdir -p bin && cp $(BINS) $(SRCS) bin/
clean:
	rm -f $(BINS)
.PHONY: all clean prebuilt
