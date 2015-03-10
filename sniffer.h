#ifndef SNIFFER_H
#define SNIFFER_H

extern int macstat_flag;

void initialize(char * interface);
void capture_packets();

void print_info();

#endif
