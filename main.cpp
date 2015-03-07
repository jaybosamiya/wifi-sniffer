#include <iostream>
#include <unistd.h>
#include <getopt.h>
#include <cstring>
#include <pcap.h>

using namespace std;

static int verbose_flag = 0;
static int debug_flag = 0;
static int help_flag = 0;
static char * interface = 0;

int main(int argc, char ** argv) {
  // Option parsing loop
  while (1) {
    int c;

    static struct option long_options[] =
      {
        {"verbose", no_argument, &verbose_flag, 1},
        {"debug"  , no_argument, &debug_flag  , 1},
        {"help"   , no_argument, &help_flag   , 1},
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

      default:
        cerr << "Invalid option. Try " << argv[0] << " -h for help. Quitting.\n";
        return -1;
      }
  }

  if (help_flag) {
    cerr << "Usage: " << argv[0] << " [options] interface\n"
            "  -v, --verbose : Output more information\n"
            "  -d, --debug   : Show debugging information\n"
            "  -h, --help    : Show this help text\n";
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

  return 0;
}
