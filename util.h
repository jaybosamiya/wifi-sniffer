/* util.h */

#ifndef UTIL_H
#define UTIL_H

#include <ctime>

void set_verbose_on();
void set_debug_on();

bool is_verbose();
bool is_debug();

void error(const char * fmt, ...);

void verbose(const char * fmt, ...);
void debug(const char * fmt, ...);

int run_command(char * const argv[]);


class Timer {
  timespec start_time;
public:
  void reset();
  float get_time();
  Timer();
};

#endif
