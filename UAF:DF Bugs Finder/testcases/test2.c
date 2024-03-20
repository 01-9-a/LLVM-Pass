#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *allocateMemory() {
    char *ptr = (char *)malloc(sizeof(char) * 16);
    return ptr;
}

int main() {
    char *a, *b;
    a = allocateMemory();
    b = a + 5;

    // Freeing the memory twice
    free(a);
    free(b); // Double free here
    return 0;
}
