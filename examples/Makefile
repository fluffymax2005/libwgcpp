# Makefile for examples/
# Using: make FILE=example1

CXX := g++
CC := gcc
CXXFLAGS := -std=c++17 -Wall -Wextra -O2
CFLAGS := -std=c11 -Wall -Wextra -O2
INCLUDES := -I../include -I../embeddable-wg-library/
BUILD_DIR := build

LIB_CXX_SRCS := $(wildcard ../src/*.cpp)
LIB_C_SRCS := ../embeddable-wg-library/wireguard.c
LIB_OBJS := $(LIB_CXX_SRCS:../src/%.cpp=$(BUILD_DIR)/lib/%.o)
LIB_OBJS += $(LIB_C_SRCS:../embeddable-wg-library/%.c=$(BUILD_DIR)/lib/%.o)

EXAMPLE_SRC := $(FILE).cpp
EXAMPLE_BIN := $(BUILD_DIR)/$(FILE)

.PHONY: all run clean list

all: $(EXAMPLE_BIN)

$(BUILD_DIR)/lib/%.o: ../src/%.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(BUILD_DIR)/lib/%.o: ../embeddable-wg-library/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(EXAMPLE_BIN): $(LIB_OBJS) $(EXAMPLE_SRC)
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $^ -o $@

run: $(EXAMPLE_BIN)
	./$(EXAMPLE_BIN)

list:
	@echo "Available examples:"
	@ls -1 *.cpp | sed 's/\.cpp//'

clean:
	rm -rf $(BUILD_DIR)
