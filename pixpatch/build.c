#include "build.h"
#define COMPILER "gcc"
#define SRC "src/main.c"
#define BIN "build/pixpatch"
#define FLAGS "-Wall -Wextra -Werror -O3"

int main(){
    run_command(COMPILER" "SRC" -o "BIN" " FLAGS);
    return 0;
}
