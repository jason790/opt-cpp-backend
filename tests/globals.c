// adapted from pg's meng thesis

int globalInt = 42;
char* globalStr = "hello world again!";
char globalChar = 'x';
double globalDouble = 3.14159;
int globalIntArray[7] = {100, 200, 300, 400, 500, 600, 700};

int main() {
  int *a = &globalInt;
  char* aliasGlobalStr = globalStr;
  return 0;
}
