#include "sniffer.h"

#include "util.h"
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <pcap.h>
#include <map>

using namespace std;

static pcap_t *handle = NULL;
static int datalink;
char * interface;

const int num_channels = 12;
int current_channel = 0;

void set_monitor_mode(char * iface) {
  interface = iface;
  char * const argv[] = {(char*)("iwconfig"),iface,(char*)("mode"),(char*)("monitor"),0};
  run_command(argv);
}

const float max_time = 10;
const float round_time = 1;

float channel_prob[num_channels+1];
int channel_time[num_channels+1];
int channel_packets[num_channels+1];

void initialize(char * interface) {
  if ( handle ) {
    error("Trying to reinitialize using interface %s",interface);
    abort();
  }

  char errbuf[BUFSIZ];

  set_monitor_mode(interface);

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

map<string,int> mac_count[num_channels+1][4];

void handleMAC(const u_char * mac, int pos) {
  char mac_c_str[13];
  mac_c_str[0] = 0;
  for ( int i = 0 ; i < 6 ; i++ ) {
    sprintf(mac_c_str,"%s%02X",mac_c_str,mac[i]);
  }
  string mac_str(mac_c_str);
  mac_count[current_channel][pos][mac_str]++;
  debug("MAC %d : %s",pos,mac_c_str);
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

  channel_packets[current_channel]++;
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

void change_channel(int channel) {
  if ( channel < 1 || channel > num_channels ) {
    error("Impossible to switch to channel %d. Quitting.",channel);
    abort();
  }
  current_channel = channel;
  char channel_no[3];
  sprintf(channel_no,"%d",channel);
  char * const argv[] = {(char*)"iwconfig",interface,(char*)"channel",channel_no,0};
  run_command(argv);
}

bool switch_to_next_channel() {
  bool ret = (current_channel==num_channels);
  static Timer ch_time;
  channel_time[current_channel]+=ch_time.get_time();
  change_channel((current_channel % num_channels) + 1);
  ch_time.reset();
  return ret;
}

void recalculate_probs() {
  const float min_speed_adder = 0.01;
  float speed[num_channels+1];
  float total_speed = 0;
  for ( int i = 1 ; i <= num_channels ; i++ ) {
    debug("Packets on channel %02d = %d",i,channel_packets);
    speed[i] = channel_packets[i]/channel_time[i];
    speed[i] += min_speed_adder;
    total_speed += speed[i];
  }

  for ( int i = 1 ; i <= num_channels ; i++ ) {
    channel_prob[i] = speed[i] / total_speed;
  }
}

void capture_packets() {
  Timer timer;
  Timer channel_timer;
  while ( timer.get_time() < max_time ) {
    pcap_pkthdr header;
    handlePacket(pcap_next(handle, &header));
    bool is_round_over;
    if ( channel_timer.get_time() > channel_prob[current_channel] * round_time ) {
      is_round_over = switch_to_next_channel();
      channel_timer.reset();
    }
    if ( is_round_over ) {
      recalculate_probs();
    }
  }
}
