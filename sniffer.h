/* sniffer.h */

#ifndef SNIFFER_H
#define SNIFFER_H

extern int macstat_flag;
extern float max_time;

void initialize(char * interface);
void capture_packets();

void print_info();

#endif
