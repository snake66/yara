#include <stdio.h>
#include <yara.h>

#include "util.h"

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  assert_true_rule_blob(
      "import \"semver\" \
      rule test { \
        condition: \
          semver.cmp(\"1.2.3\", \"1.2.3\") == 0 \
      }",
      "A");

  assert_true_rule_blob(
      "import \"semver\" \
      rule test { \
        condition: \
          semver.cmp(\"1.2.3\", \"1.2.4\") < 0 \
      }",
      "A");

  assert_true_rule_blob(
      "import \"semver\" \
      rule test { \
        condition: \
          semver.cmp(\"1.2.10\", \"1.2.4\") > 0 \
      }",
      "A");

  yr_finalize();

  YR_DEBUG_FPRINTF(
      1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
