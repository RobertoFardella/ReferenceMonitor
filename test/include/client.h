#include <unistd.h>
#include <stdio.h>
#include <syscall.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
enum rm_state {
    ON,
    OFF,
    REC_ON,
    REC_OFF
};

extern void displayMenu();