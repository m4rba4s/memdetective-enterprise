# Memory Inspector CLI - Professional Makefile
# Senior-grade C/C++ security tool for forensics and memory analysis

CC = gcc
CXX = g++
CFLAGS = -std=c11 -Wall -Wextra -Werror -pedantic -O2 -g -D_GNU_SOURCE
CXXFLAGS = -std=c++17 -Wall -Wextra -Werror -pedantic -O2 -g
LDFLAGS = -lpthread
# LDFLAGS = -lyara -lpthread  # Enable when YARA is available

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
TEST_DIR = tests

# Source files
CORE_SRCS = $(SRC_DIR)/core/core.c $(SRC_DIR)/core/logger.c
MEMORY_SRCS = $(SRC_DIR)/memory/analyzer.c
YARA_SRCS = $(SRC_DIR)/yara/yara_scanner.c
DUMP_SRCS = $(SRC_DIR)/dump/dump_engine.c
UI_SRCS = $(SRC_DIR)/ui/cli.c
PLATFORM_SRCS = $(SRC_DIR)/platform/platform.c $(SRC_DIR)/platform/linux/linux_memory.c

ALL_SRCS = $(CORE_SRCS) $(MEMORY_SRCS) $(YARA_SRCS) $(DUMP_SRCS) $(UI_SRCS) $(PLATFORM_SRCS)
MAIN_SRC = $(SRC_DIR)/main.c

# Object files
OBJS = $(ALL_SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)
MAIN_OBJ = $(BUILD_DIR)/main.o

# Executable
TARGET = memory-inspector

# Default target
all: $(TARGET)

# Create build directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/{core,memory,yara,dump,ui,platform/linux}

# Compile object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Link executable
$(TARGET): $(OBJS) $(MAIN_OBJ)
	$(CC) $(OBJS) $(MAIN_OBJ) -o $@ $(LDFLAGS)

# Install dependencies (Fedora)
deps-fedora:
	sudo dnf install -y yara-devel ncurses-devel gcc make

# Clean
clean:
	rm -rf $(BUILD_DIR) $(TARGET)

# Tests
test: $(TARGET)
	cd $(TEST_DIR) && $(MAKE)

# Debug build
debug: CFLAGS += -DDEBUG -g3 -O0
debug: $(TARGET)

# Static analysis
lint:
	cppcheck --enable=all --std=c11 $(SRC_DIR)/

# Format code
format:
	clang-format -i $(SRC_DIR)/**/*.c $(INC_DIR)/*.h

.PHONY: all clean test debug deps-fedora lint format