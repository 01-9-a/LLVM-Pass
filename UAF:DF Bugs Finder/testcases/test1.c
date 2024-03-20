#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define BUFSIZER1   512
#define BUFSIZER2   ((BUFSIZER1/2) - 8)

int main(int argc, char **argv) {
    char *buf1R1;
    char *buf1R2;
    char *temp;

    buf1R1 = (char *) malloc(BUFSIZER1);
    buf1R2 = (char *) malloc(BUFSIZER1);
    strcpy(buf1R1, "Initial Content: ");

    temp = buf1R2 + 10;
    free(buf1R2);

    strncat(temp, argv[1], BUFSIZER1 - strlen(temp) - 1); // Use after 
free using strncat

    free(buf1R2);

    return 0;
}
