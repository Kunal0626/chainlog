// A ~60-line assertion-based test runner.
//
// Deliberately not gtest or Catch2: the whole point of this project is that
// every byte is accounted for, and a test framework that needs its own build
// system would be the largest dependency in the repo. What is actually needed
// is TEST(), CHECK(), CHECK_EQ() and a non-zero exit status, which is this.
#ifndef CHAINLOG_TESTS_TEST_H
#define CHAINLOG_TESTS_TEST_H

#include <string>
#include <vector>

namespace chainlog_test {

struct Case {
  const char* name;
  void (*fn)();
};

// Function-local static, so registration from any translation unit works
// regardless of static initialisation order across objects.
std::vector<Case>& registry();

// Runs every registered case; returns the number of failed cases.
int run_all();

void report_failure(const char* file, int line, const std::string& msg);

struct Registrar {
  Registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

// Value printers for CHECK_EQ diagnostics. A failing test should tell you what
// it got, not just that it was unhappy.
inline std::string to_text(const std::string& s) { return s; }
inline std::string to_text(const char* s) { return s ? std::string(s) : "(null)"; }
inline std::string to_text(bool b) { return b ? "true" : "false"; }
template <typename T>
std::string to_text(const T& v) {
  return std::to_string(v);
}

}  // namespace chainlog_test

#define TEST(name)                                               \
  static void name();                                            \
  static ::chainlog_test::Registrar reg_##name(#name, name);     \
  static void name()

#define CHECK(cond)                                                       \
  do {                                                                    \
    if (!(cond)) {                                                        \
      ::chainlog_test::report_failure(__FILE__, __LINE__,                  \
                                      "CHECK failed: " #cond);            \
    }                                                                     \
  } while (0)

#define CHECK_EQ(a, b)                                                    \
  do {                                                                    \
    auto chainlog_lhs = (a);                                              \
    auto chainlog_rhs = (b);                                              \
    if (!(chainlog_lhs == chainlog_rhs)) {                                \
      ::chainlog_test::report_failure(                                    \
          __FILE__, __LINE__,                                             \
          std::string("CHECK_EQ failed: " #a " == " #b "\n") +            \
              "         left:  " + ::chainlog_test::to_text(chainlog_lhs) + \
              "\n         right: " + ::chainlog_test::to_text(chainlog_rhs)); \
    }                                                                     \
  } while (0)

#endif  // CHAINLOG_TESTS_TEST_H
