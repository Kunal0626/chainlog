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
LIB_SRCS  = src/sha256.cpp src/hex.cpp
TEST_SRCS = tests/test.cpp tests/test_sha256.cpp
TOOL_SRCS = tools/cl_sha256.cpp

REL_LIB_OBJS  = $(LIB_SRCS:%.cpp=$(REL_DIR)/%.o)
REL_TOOL_OBJS = $(TOOL_SRCS:%.cpp=$(REL_DIR)/%.o)
TST_OBJS      = $(LIB_SRCS:%.cpp=$(TST_DIR)/%.o) $(TEST_SRCS:%.cpp=$(TST_DIR)/%.o)

CL_SHA256 = $(REL_DIR)/cl-sha256
TESTBIN   = $(TST_DIR)/chainlog-tests

.PHONY: all test unit oracle clean
all: $(CL_SHA256)

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

$(CL_SHA256): $(REL_LIB_OBJS) $(REL_TOOL_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(REL_FLAGS) $(REL_LIB_OBJS) $(REL_TOOL_OBJS) -o $@

$(TESTBIN): $(TST_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(TST_FLAGS) $(TST_OBJS) -o $@

# --- test targets ----------------------------------------------------------
# `unit` is the sanitized C++ suite; `oracle` cross-checks our SHA-256 against
# the system implementations. `test` runs both, and is what CI (and you) runs.

unit: $(TESTBIN)
	$(TESTBIN)

oracle: $(CL_SHA256)
	tests/oracle_sha256.sh $(CL_SHA256)

test: unit oracle

clean:
	rm -rf $(BUILD)

-include $(REL_LIB_OBJS:.o=.d) $(REL_TOOL_OBJS:.o=.d) $(TST_OBJS:.o=.d)
