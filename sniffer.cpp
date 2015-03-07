#include "sniffer.h"

#include "util.h"
#include <cstdlib>
#include <pcap.h>

static pcap_t *handle = NULL;

void initialize(char * interface) {
  if ( handle ) {
    error("Trying to reinitialize using interface %s",interface);
    abort();
  }

  char errbuf[BUFSIZ];

  handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    error("Couldn't open interface %s",interface);
    abort();
  }

  verbose("Opened interface %s.",interface);
  debug("Datalink is %d.",pcap_datalink(handle));
}
