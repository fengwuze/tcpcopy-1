
#ifndef  _UDP_SESSION_H_INC
#define  _UDP_SESSION_H_INC


/* global functions */
int  init_sess_table();
void destroy_sess_table();
bool proc_ingress(tc_ip_header_t *ip, tc_udp_header_t *udp);
bool proc_outgress(unsigned char *packet);
bool check_ingress_pack_needed(tc_ip_header_t *ip);
void interval_dispose(tc_event_timer_t *evt);
void output_stat();

#endif   /* ----- #ifndef _UDP_SESSION_H_INC ----- */

