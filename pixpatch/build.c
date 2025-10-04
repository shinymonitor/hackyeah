#include "build.h"

#define C_COMPILER "gcc"
#define C_SRC "src/main.c lib/monocypher.c lib/monocypher-ed25519.c"
#define C_BIN "build/pixpatch"
#define C_FLAGS "-Wall -Wextra -Werror -pedantic -O3"

int main(){
    fetch_to_lib_if_missing("monocypher.h", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.h");
    fetch_to_lib_if_missing("monocypher.c", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.c");
    fetch_to_lib_if_missing("monocypher-ed25519.h", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.h");
    fetch_to_lib_if_missing("monocypher-ed25519.c", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.c");
    
    run_command(C_COMPILER" "C_SRC" -o "C_BIN" "C_FLAGS);
    return 0;
}
