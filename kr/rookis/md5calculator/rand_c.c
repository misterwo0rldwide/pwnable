#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(0));
	rand(); // First random is not calculated in my_hash
    for (int i = 0; i < 7; i++) {
        printf("%d\n", rand());
    }
    return 0;
}
