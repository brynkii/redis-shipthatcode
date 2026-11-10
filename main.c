#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX_ARGS 64
#define MAX_LINE 4096

int parse_args(char *line, char *args[], int max_args) {
    int count = 0;
    int in_quotes = 0;
    char *start = NULL;

    for (char *p = line; *p && count < max_args; p++) {
        if (*p == '"' && !in_quotes) { in_quotes = 1; start = p + 1; }
        else if (*p == '"' && in_quotes) { in_quotes = 0; *p = '\0'; args[count++] = start; start = NULL; }
        else if (*p == ' ' && !in_quotes) {
            if (start) { *p = '\0'; args[count++] = start; start = NULL; }
        } else if (!start) { start = p; }
    }
    if (start) args[count++] = start;
    return count;
}

void str_toupper(char *s) {
    for (; *s; s++) *s = toupper(*s);
}

void handle_command(char *args[], int argc) {
    char cmd[256];
    strncpy(cmd, args[0], sizeof(cmd) - 1);
    str_toupper(cmd);

    if (strcmp(cmd, "PING") == 0) {
        /* TODO: Print "+PONG\r\n" for no args */
        /* TODO: Print bulk string for PING <message> */
        return;
    }

    printf("-ERR unknown command\r\n");
    fflush(stdout);
}

int main() {
    char line[MAX_LINE];
    char *args[MAX_ARGS];

    while (fgets(line, sizeof(line), stdin)) {
        /* trim newline */
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;
        int argc = parse_args(line, args, MAX_ARGS);
        if (argc > 0) handle_command(args, argc);
    }
    return 0;
}
