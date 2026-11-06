# ChainLog -- tamper-evident audit log engine.
#
# A plain Makefile on purpose: CMake is not installed on the development
# machine and buys nothing for a project this size. Written against GNU Make
# 3.81 (the version Apple ships), so no `::=`, no `$(file ...)`, no .ONESHELL.

CXX      ?= clang++
CXXSTD    = -std=c++17
WARN      = -Wall -Wextra -Wpedantic
INCLUDES  = -Iinclude

# Release build: optimised, no sanitizers. Used for the CLI, tools, benchmarks.
REL_FLAGS = $(CXXSTD) $(WARN) $(INCLUDES) -O2

# Test build: AddressSanitizer catches out-of-bounds and use-after-free in the
# byte-slinging code; UBSan catches signed overflow, bad shifts and misaligned
# loads. -fno-sanitize-recover makes UBSan abort instead of printing and
# carrying on, so a test can never pass while quietly relying on UB.
# Note: unsigned wraparound is well-defined and SHA-256 depends on it, so
# -fsanitize=integer is deliberately NOT enabled.
TST_FLAGS = $(CXXSTD) $(WARN) $(INCLUDES) -O1 -g -fno-omit-frame-pointer \
            -fsanitize=address,undefined -fno-sanitize-recover=undefined

BUILD   = build
REL_DIR = $(BUILD)/release
TST_DIR = $(BUILD)/test

# Engine sources, shared by the release and test builds.
LIB_SRCS  = src/sha256.cpp src/hex.cpp src/crc32.cpp src/fileio.cpp \
            src/record.cpp src/log.cpp
TEST_SRCS = tests/test.cpp tests/test_sha256.cpp tests/test_crc32.cpp \
            tests/test_record.cpp tests/test_log.cpp tests/log_fixture.cpp
CLI_SRCS  = src/main.cpp
TOOL_SRCS = tools/cl_sha256.cpp tools/cl_crc32.cpp

REL_LIB_OBJS  = $(LIB_SRCS:%.cpp=$(REL_DIR)/%.o)
REL_CLI_OBJS  = $(CLI_SRCS:%.cpp=$(REL_DIR)/%.o)
REL_TOOL_OBJS = $(TOOL_SRCS:%.cpp=$(REL_DIR)/%.o)
TST_OBJS      = $(LIB_SRCS:%.cpp=$(TST_DIR)/%.o) $(TEST_SRCS:%.cpp=$(TST_DIR)/%.o)

CHAINLOG  = $(REL_DIR)/chainlog
CL_SHA256 = $(REL_DIR)/cl-sha256
CL_CRC32  = $(REL_DIR)/cl-crc32
TESTBIN   = $(TST_DIR)/chainlog-tests

# The sanitized build of the CLI: the shell tests drive this one, so that
# ASan/UBSan see the real append and verify paths, not just the unit tests.
TST_CLI_OBJS = $(LIB_SRCS:%.cpp=$(TST_DIR)/%.o) $(CLI_SRCS:%.cpp=$(TST_DIR)/%.o)
CHAINLOG_ASAN = $(TST_DIR)/chainlog

.PHONY: all test unit oracle cli clean
all: $(CHAINLOG) $(CL_SHA256) $(CL_CRC32)

# --- compile rules ---------------------------------------------------------
# One pattern rule per build flavour; -MMD -MP emits header dependencies so
# editing a header rebuilds everything that includes it.

$(REL_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(REL_FLAGS) -MMD -MP -c $< -o $@

$(TST_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TST_FLAGS) -MMD -MP -c $< -o $@

# --- link rules ------------------------------------------------------------

$(CHAINLOG): $(REL_LIB_OBJS) $(REL_CLI_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(REL_FLAGS) $(REL_LIB_OBJS) $(REL_CLI_OBJS) -o $@

$(CHAINLOG_ASAN): $(TST_CLI_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(TST_FLAGS) $(TST_CLI_OBJS) -o $@

$(CL_SHA256): $(REL_LIB_OBJS) $(REL_DIR)/tools/cl_sha256.o
	@mkdir -p $(dir $@)
	$(CXX) $(REL_FLAGS) $(REL_LIB_OBJS) $(REL_DIR)/tools/cl_sha256.o -o $@

$(CL_CRC32): $(REL_LIB_OBJS) $(REL_DIR)/tools/cl_crc32.o
	@mkdir -p $(dir $@)
	$(CXX) $(REL_FLAGS) $(REL_LIB_OBJS) $(REL_DIR)/tools/cl_crc32.o -o $@

$(TESTBIN): $(TST_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(TST_FLAGS) $(TST_OBJS) -o $@

# --- test targets ----------------------------------------------------------
# `unit` is the sanitized C++ suite; `oracle` cross-checks our SHA-256 against
# the system implementations. `test` runs both, and is what CI (and you) runs.

unit: $(TESTBIN)
	$(TESTBIN)

oracle: $(CL_SHA256) $(CL_CRC32) $(CHAINLOG)
	tests/oracle_sha256.sh $(CL_SHA256)
	tests/oracle_crc32.sh $(CL_CRC32)
	tests/oracle_format.sh $(CHAINLOG)

# End-to-end CLI checks, run against the sanitized binary.
cli: $(CHAINLOG_ASAN)
	tests/cli.sh $(CHAINLOG_ASAN)

test: unit oracle cli

clean:
	rm -rf $(BUILD)

-include $(REL_LIB_OBJS:.o=.d) $(REL_CLI_OBJS:.o=.d) $(REL_TOOL_OBJS:.o=.d) \
         $(TST_OBJS:.o=.d) $(TST_CLI_OBJS:.o=.d)
