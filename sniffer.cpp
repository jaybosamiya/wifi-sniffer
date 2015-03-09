#include "sniffer.h"

#include "util.h"
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <pcap.h>

using namespace std;

static pcap_t *handle = NULL;
static int datalink;

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

  datalink = pcap_datalink(handle);

  verbose("Opened interface %s.",interface);
  debug("Datalink is %d.", datalink);
}

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct prism_value{
  u_int32_t did;
  u_int16_t status;
  u_int16_t len;
  u_int32_t data;
};

struct prism_header{
  u_int32_t msgcode;
  u_int32_t msglen;
  prism_value hosttime;
  prism_value mactime;
  prism_value channel;
  prism_value rssi;
  prism_value sq;
  prism_value signal;
  prism_value noise;
  prism_value rate;
  prism_value istx;
  prism_value frmlen;
};

void handleMAC(const u_char * mac, int pos) {
  char mac_c_str[13];
  mac_c_str[0] = 0;
  for ( int i = 0 ; i < 6 ; i++ ) {
    sprintf(mac_c_str,"%s%02X",mac_c_str,mac[i]);
  }
  string mac_str(mac_c_str);
  debug("MAC %d : %s",pos,mac_c_str);
  // TODO: Add to the buckets
}

void handlePacket(const u_char* packet) {
  if ( datalink ==	DLT_PRISM_HEADER ) {
    prism_header* rth1 = (prism_header*)(packet);
    packet = packet + rth1->msglen;
  }

  // TODO: Check if the +4 should come after this line or before (during the PRISM skip)

  for ( int i = 0 ; i < 4 ; i++ ) {
    handleMAC(packet+4+(i*6),i);
  }
}

class Timer {
  clock_t start_time;
public:
  void reset() { start_time = clock(); }
  float get_time() {
    return (float(clock()-start_time)/CLOCKS_PER_SEC);
  }
  Timer() { reset(); }
};

const float max_time = 10;

void capture_packets() {
  static Timer timer;
  while ( timer.get_time() < max_time ) {
    pcap_pkthdr header;
    handlePacket(pcap_next(handle, &header));
  }
}
