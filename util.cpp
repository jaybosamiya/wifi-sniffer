#include "util.h"

#include <iostream>
#include <cstdarg>
#include <cstdio>

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

