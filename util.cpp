#include "util.h"

#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <unistd.h>
#include <sys/wait.h>

using namespace std;

static int verbose_flag = 0;
static int debug_flag = 0;

const int BUFSIZE(200);
static char TEMPOUT[BUFSIZE];

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

void error(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  cerr << TEMPOUT << endl;
}

void verbose(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  if ( verbose_flag ) {
    cerr << TEMPOUT << endl;
  }
}

void debug(const char * fmt, ...) {
  va_list argp;

  va_start(argp, fmt);
  vsnprintf(TEMPOUT, sizeof(TEMPOUT), fmt, argp);
  va_end(argp);

  if ( debug_flag ) {
    cerr << TEMPOUT << endl;
  }
}

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
