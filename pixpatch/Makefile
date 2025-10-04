default:
	wget -q --show-progress https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.h -O lib/monocypher.h
	wget -q --show-progress https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.c -O lib/monocypher.c
	wget -q --show-progress https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.h -O lib/monocypher-ed25519.h
	wget -q --show-progress https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.c -O lib/monocypher-ed25519.c
	gcc src/main.c lib/monocypher.c lib/monocypher-ed25519.c -o build/pixpatch -Wall -Wextra -Werror -pedantic -O3