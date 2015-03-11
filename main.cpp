/* main.cpp */

#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <cstring>
#include <cstdlib>
#include "util.h"
#include "sniffer.h"

using namespace std;

static int verbose_flag = 0;
static int debug_flag = 0;
static int help_flag = 0;
static char * interface = 0;

int main(int argc, char ** argv) {
  cout << "WiFi Sniffer\n"
          "------------\tBy Jay H. Bosamiya\n"
          "            \t------------------\n\n";

  // Make sure that only root can run this program
  if ( geteuid() ) {
    help_flag = true;
  }

  if ( argc == 1 ) {
    help_flag = true;
  }

  // Option parsing loop
  while (1) {
    int c;

    static struct option long_options[] =
      {
        {"macstat"  , no_argument      , &macstat_flag  ,  1},
        {"time"     , required_argument, NULL           ,'t'},
        {"verbose"  , no_argument      , &verbose_flag  ,  1},
        {"debug"    , no_argument      , &debug_flag    ,  1},
        {"help"     , no_argument      , &help_flag     ,  1},
        {0, 0, 0, 0}
      };
    int option_index = 0;

    c = getopt_long_only (argc, argv, "",
                     long_options, &option_index);

    /* Detect the end of the options. */
    if (c == -1)
      break;

    switch (c)
      {
      case 0:
        break;

      case 't':
        max_time = atoi(optarg);
        break;

      default:
        cerr << "Invalid option. Try " << argv[0] << " -h for help. Quitting.\n";
        return -1;
      }
  }

  if (help_flag) {
    cerr << "Usage: " << argv[0] << " [options] interface\n"
            "  -m, --macstat   : Show number of detections of each MAC and timestamps\n"
            "  -t, --time t    : Run sniffer for t seconds (default: 60)\n"
            "  -v, --verbose   : Output more information\n"
            "  -d, --debug     : Show debugging information\n"
            "  -h, --help      : Show this help text\n"
            "\n"
            "Note: This program needs to be run as root\n"
    ;
    return 0;
  }

  while (optind < argc) {
    if ( ! interface ) {
      interface = strdup(argv[optind++]);
    } else {
      cerr << "Too many interfaces. Try " << argv[0] << " -h for help. Quitting.\n";
      return -1;
    }
  }

  if ( ! interface ) {
    cerr << "No interface specified. Try " << argv[0] << " -h for help. Quitting.\n";
    return -1;
  }

  if ( verbose_flag ) {
    set_verbose_on();
  }

  if ( debug_flag ) {
    set_debug_on();
  }

  // Do actual work (from sniffer.* files)
  initialize(interface);
  capture_packets();
  print_info();

  return 0;
}
