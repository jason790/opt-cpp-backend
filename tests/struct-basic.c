#include <stdlib.h>

// from https://en.wikipedia.org/wiki/Struct_(C_programming_language)

// regular
struct Account {
   int account_number;
   char *first_name;
   char *last_name;
   float balance;
};

// typedef version
typedef struct {
   int    xxx;
   int    yyy;
} Point;

int main() {
  struct Account my_account;
  my_account.account_number = 42;
  my_account.first_name = "Philip";
  my_account.last_name = "Guo";
  my_account.balance = 3.14159;

  Point my_point;
  my_point.xxx = 12345;
  my_point.yyy = 54321;
  return 0;
}
