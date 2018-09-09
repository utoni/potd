#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define APP_NAME "init"

int main(void)
{
    if (getppid() != 0 || getpid() != 1) {
        fprintf(stderr, "%s: must be started as PID 1\n", APP_NAME);
        return 1;
    }

    return 0;
}
