/*
 * =====================================================================================
 *
 *       Filename:  zdclient.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/06/2009 03:47:25 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *        Company:  
 *
 * =====================================================================================
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <getopt.h>
#include <iconv.h>
#include "md5.h"

/* ZDClient Version */
#define ZDC_VER "1.0"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

struct eap_header {
    u_char eapol_v;
    u_char eapol_t;
    u_short eapol_length;
    u_char eap_t;
    u_char eap_id;
    u_short eap_length;
    u_char eap_op;
    u_char eap_v_length;
    u_char eap_md5_challenge[16];
};

struct dcba_tailer {
    bpf_u_int32     local_ip;
    bpf_u_int32     local_mask;
    bpf_u_int32     local_gateway;
    bpf_u_int32     local_dns;
    u_char          username_md5[16];
    u_char          client_ver[13];
};

enum EAPType {
    EAPOL_START,
    EAPOL_LOGOFF,
    EAP_REQUEST_IDENTITY,
    EAP_RESPONSE_IDENTITY,
    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
    EAP_REQUETS_MD5_CHALLENGE,
    EAP_RESPONSE_MD5_CHALLENGE,
    EAP_SUCCESS,
    EAP_FAILURE,
    ERROR
};

enum STATE {
   READY,
   STARTED,
   ID_AUTHED,
   ONLINE
};

void    send_eap_packet(enum EAPType send_type);
void    show_usage();
char*   get_md5_digest(const char* str, size_t len);
void    action_by_eap_type(enum EAPType pType, 
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const u_char *packet);
void    send_eap_packet(enum EAPType send_type);
void    init_frames();
void    init_info();
void    init_device();
void    init_arguments(int *argc, char ***argv);
int     set_device_new_ip();
void    fill_password_md5(u_char attach_key[], u_int id);
int     program_running_check();
void    daemon_init(void);
void    show_local_info();
void    print_server_info (const u_char *packet, u_int packetlength);
int     code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen);


void
get_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet);

