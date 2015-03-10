#ifndef UTIL_H
#define UTIL_H

void set_verbose_on();
void set_debug_on();

bool is_verbose();
bool is_debug();

void error(const char * fmt, ...);

void verbose(const char * fmt, ...);
void debug(const char * fmt, ...);

void run_command(char * const argv[]);

#endif
