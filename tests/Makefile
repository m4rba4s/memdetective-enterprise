# Memory Inspector CLI - Test Suite Makefile
# Professional testing with GoogleTest integration

CC = gcc
CXX = g++
CFLAGS = -std=c11 -Wall -Wextra -g -O0
CXXFLAGS = -std=c++17 -Wall -Wextra -g -O0 -coverage
LDFLAGS = -lpthread -lgcov --coverage

# Directories
ROOT_DIR = ..
SRC_DIR = $(ROOT_DIR)/src
INC_DIR = $(ROOT_DIR)/include
BUILD_DIR = build
UNIT_DIR = unit
INTEGRATION_DIR = integration

# Source files (excluding main.c)
CORE_SRCS = $(SRC_DIR)/core/core.c $(SRC_DIR)/core/logger.c
MEMORY_SRCS = $(SRC_DIR)/memory/analyzer.c
YARA_SRCS = $(SRC_DIR)/yara/yara_scanner.c
DUMP_SRCS = $(SRC_DIR)/dump/dump_engine.c
UI_SRCS = $(SRC_DIR)/ui/cli.c
PLATFORM_SRCS = $(SRC_DIR)/platform/platform.c $(SRC_DIR)/platform/linux/linux_memory.c

LIB_SRCS = $(CORE_SRCS) $(MEMORY_SRCS) $(YARA_SRCS) $(DUMP_SRCS) $(UI_SRCS) $(PLATFORM_SRCS)

# Object files
LIB_OBJS = $(LIB_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Test executables  
INTEGRATION_TESTS = $(BUILD_DIR)/test_basic_functionality

ALL_TESTS = $(INTEGRATION_TESTS)

# Default target
all: $(ALL_TESTS)

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/{core,memory,yara,dump,ui,platform/linux}

# Compile library object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Unit test executables
$(BUILD_DIR)/test_dump_engine: $(UNIT_DIR)/test_dump_engine.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/test_memory_analyzer: $(UNIT_DIR)/test_memory_analyzer.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/test_yara_scanner: $(UNIT_DIR)/test_yara_scanner.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

$(BUILD_DIR)/test_core_functions: $(UNIT_DIR)/test_core_functions.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# Integration test executables
$(BUILD_DIR)/test_basic_functionality: $(INTEGRATION_DIR)/test_basic_functionality.c
	$(CC) $(CFLAGS) $< -o $@

# Run all tests
test: $(ALL_TESTS)
	@echo "=== Running Integration Tests ==="
	@for test in $(INTEGRATION_TESTS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
		echo ""; \
	done
	@echo "🎉 All tests passed!"

# Run only unit tests
unit-test: $(UNIT_TESTS)
	@echo "=== Running Unit Tests Only ==="
	@for test in $(UNIT_TESTS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
		echo ""; \
	done

# Run only integration tests
integration-test: $(INTEGRATION_TESTS)
	@echo "=== Running Integration Tests Only ==="
	@for test in $(INTEGRATION_TESTS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
		echo ""; \
	done

# Generate coverage report
coverage: test
	@echo "=== Generating Coverage Report ==="
	gcov $(LIB_SRCS)
	lcov --capture --directory . --output-file coverage.info
	lcov --remove coverage.info '/usr/*' --output-file coverage.info
	lcov --list coverage.info
	genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/"

# Run tests with valgrind for memory leak detection
valgrind-test: $(ALL_TESTS)
	@echo "=== Running Tests with Valgrind ==="
	@for test in $(ALL_TESTS); do \
		echo "Running $$test with valgrind..."; \
		valgrind --leak-check=full --error-exitcode=1 $$test || exit 1; \
		echo ""; \
	done

# Run tests with address sanitizer
asan-test: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan-test: LDFLAGS += -fsanitize=address
asan-test: clean $(ALL_TESTS)
	@$(MAKE) test

# Run tests with thread sanitizer
tsan-test: CFLAGS += -fsanitize=thread -fno-omit-frame-pointer
tsan-test: LDFLAGS += -fsanitize=thread
tsan-test: clean $(ALL_TESTS)
	@$(MAKE) test

# Performance benchmarks
benchmark: $(BUILD_DIR)/benchmark
	@echo "=== Running Performance Benchmarks ==="
	$(BUILD_DIR)/benchmark

$(BUILD_DIR)/benchmark: benchmark/benchmark.c $(LIB_OBJS)
	$(CC) $(CFLAGS) -I$(INC_DIR) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# Clean
clean:
	rm -rf $(BUILD_DIR) *.gcov *.gcda *.gcno coverage.info coverage_report/

# Install test dependencies
deps:
	@echo "Installing test dependencies..."
	sudo apt-get update
	sudo apt-get install -y lcov valgrind

.PHONY: all test unit-test integration-test coverage valgrind-test asan-test tsan-test benchmark clean deps