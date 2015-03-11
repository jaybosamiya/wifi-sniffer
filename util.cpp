/* util.cpp */

#include "util.h"

#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>

using namespace std;

static int verbose_flag = 0;
static int debug_flag = 0;

const int BUFSIZE(200);
static char TEMPOUT[BUFSIZE];

// Flag management

void set_verbose_on() {
  verbose_flag = 1;
}

void set_debug_on() {
  debug_flag = 1;
  verbose_flag = 1;
}

bool is_verbose() {
  return verbose_flag;
}
bool is_debug() {
  return debug_flag;
}

// Display error to stderr
void error(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  cerr << TEMPOUT << endl;
}

// Display message only when verbose
void verbose(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  if ( verbose_flag ) {
    cout << TEMPOUT << endl;
  }
}

// Display message only when debugging
void debug(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  if ( debug_flag ) {
    cout << TEMPOUT << endl;
  }
}

// Run a command-line utility
// Run using fork-exec combo
int run_command(char * const argv[]) {
  debug("Running program %s",argv[0]);

  pid_t p = fork();

  if ( p == 0 ) {
    if ( execvp(argv[0],argv) ) {
      error("Error during execution of %s",argv[0]);
      abort();
    }
  } else {
    int status;
    waitpid(p,&status,0);
    debug("%s returned value %d",argv[0],status);
    return status;
  }
}

// Timer utilities

float diff(timespec start, timespec end) {
  timespec temp;
  if ((end.tv_nsec-start.tv_nsec)<0) {
    temp.tv_sec = end.tv_sec-start.tv_sec-1;
    temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
  } else {
    temp.tv_sec = end.tv_sec-start.tv_sec;
    temp.tv_nsec = end.tv_nsec-start.tv_nsec;
  }
  return (float)temp.tv_sec + 1e-9 * temp.tv_nsec;
}

Timer::Timer() {
  reset();
}

void Timer::reset() {
 clock_gettime(CLOCK_MONOTONIC_COARSE,&start_time);
}

float Timer::get_time() {
  timespec temp;
  clock_gettime(CLOCK_MONOTONIC_COARSE,&temp);
  return diff(start_time,temp);
}
