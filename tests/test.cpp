#include "test.h"

#include <cstdio>

namespace chainlog_test {
namespace {

int g_failures_in_case = 0;

}  // namespace

std::vector<Case>& registry() {
  static std::vector<Case> cases;
  return cases;
}

void report_failure(const char* file, int line, const std::string& msg) {
  ++g_failures_in_case;
  std::printf("  %s:%d: %s\n", file, line, msg.c_str());
}

int run_all() {
  int failed = 0;
  for (size_t i = 0; i < registry().size(); ++i) {
    const Case& c = registry()[i];
    g_failures_in_case = 0;
    std::printf("-- %s\n", c.name);
    c.fn();
    if (g_failures_in_case == 0) {
      std::printf("ok   %s\n", c.name);
    } else {
      std::printf("FAIL %s (%d assertion(s))\n", c.name, g_failures_in_case);
      ++failed;
    }
  }
  std::printf("\n%zu case(s), %d failed\n", registry().size(), failed);
  return failed;
}

}  // namespace chainlog_test

int main() {
  // Non-zero exit on any failure, so `make test` and CI stop.
  return chainlog_test::run_all() == 0 ? 0 : 1;
}
