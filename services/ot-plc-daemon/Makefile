# ==============================================================================
# SecuriGlass Factory OS - Makefile pour le Démon C PLC (Niveau 1 OT)
# Normes : POSIX C11, 0 Warning (-Wall -Wextra -Werror -pedantic), 0 Fuite
# ==============================================================================

CC ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L -Iinclude -pthread -O2
DEBUG_CFLAGS = -std=c11 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L -Iinclude -pthread -g -O0

SRCS = src/main.c src/plc_simulator.c src/plc_modbus.c
OBJS = $(SRCS:.c=.o)
TARGET = bin/plc_daemon
TEST_TARGET = bin/plc_test

SAN_FLAGS = -std=c11 -Wall -Wextra -Werror -pedantic -D_POSIX_C_SOURCE=200809L -Iinclude -pthread -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer
TEST_SRCS = tests/test_plc.c src/plc_simulator.c src/plc_modbus.c

.PHONY: all debug clean test fuzz lib sanitize valgrind doc

all: $(TARGET) lib

$(TARGET): $(OBJS)
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lm

lib: bin/libplc.dylib

bin/libplc.dylib: src/plc_simulator.c src/plc_modbus.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $^ -lm

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
	@./$(TEST_TARGET)

fuzz: bin/plc_fuzz_test
	@./bin/plc_fuzz_test

bin/plc_fuzz_test: tests/plc_fuzz_test.c src/plc_simulator.c src/plc_modbus.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ -lm

$(TEST_TARGET): tests/plc_test.c src/plc_simulator.c src/plc_modbus.c
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $^ -lm

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: clean $(TARGET)

clean:
	rm -rf src/*.o tests/*.o bin/ html/ latex/

valgrind: debug
	valgrind --leak-check=full \
	         --show-leak-kinds=all \
	         --track-origins=yes \
	         --error-exitcode=1 \
	         ./$(TARGET) --test-mode --duration 5

doc:
	@mkdir -p docs/doxygen
	doxygen Doxyfile
