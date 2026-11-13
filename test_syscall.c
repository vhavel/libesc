#include <unistd.h>

int main() {
    write(1, "Hello\n", 6);
    _exit(0);
}
