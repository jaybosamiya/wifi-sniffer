/* protocol_headers.h */

// Define some structures to be used for correct header decryption

#ifndef PROTOCOL_HEADERS_H
#define PROTOCOL_HEADERS_H

#include <pcap.h>

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

#endif
