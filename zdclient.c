#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include "md5.h"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_eap_header {
    u_char eapol_v;
    u_char eapol_t;
    u_short eapol_length;
    u_char eap_t;
    u_char eap_ask_t;
    u_short eap_length;
    u_char eap_op;
    u_char eap_v_length;
    u_char eap_md5_challenge[16];
};

enum EAPType {
        EAPOL_START,
        EAPOL_LOGOFF,
        EAP_REQUEST_IDENTITY,
        EAP_RESPONSE_IDENTITY,
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

void fill_password_md5(u_char attach_key[]);
void send_eap_packet(enum EAPType send_type);


char *dev;			/* capture device name */
char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

enum STATE state;

pcap_t *handle;				/* packet capture handle */

int         dhcp_on;
int         background;
char        *dev = NULL;
char        *username = NULL;
char        *password = NULL;
char        *gateway = NULL;
char        *dns = NULL;

int         username_length;
int         password_length;

//u_char      dhcp_on;
u_int       local_ip;			/* ip */
u_int       local_mask;			/* subnet mask */
u_int       local_gateway = -1;
u_int       local_dns = -1;
u_char      client_ver[] = "3.4.2006.1027";
u_char      local_mac[ETHER_ADDR_LEN];
u_char      muticast_mac[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

u_char      eapol_start[18];
u_char      eapol_logoff[18];
u_char      *eap_response_ident;
u_char      *eap_response_md5ch;

u_int         live_count = 0;

/* Option struct for progrm run arguments */
static struct option long_options[] =
    {
    {"help",        no_argument,        0,              'h'},
    {"background",  no_argument,        &background,    1},
    {"dhcp",        no_argument,        &dhcp_on,       1},
    {"device",      required_argument,  0,              2},
    {"username",    required_argument,  0,              'u'},
    {"password",    required_argument,  0,              'p'},
    {"gateway",     required_argument,  0,              'g'},
    {"dns",         required_argument,  0,              'd'},
    {0, 0, 0, 0}
    };

// debug function
void 
print_hex(u_char *array, int count)
{
    int i;
    for(i = 0; i < count; i++){
        printf("%02x ", array[i]);
    }
    printf("\n");
}

void
show_usage()
{
    printf( "\n"
            "ZDC Client 0.1 \n"
            "\t  -- Supllicant for DigiChina Authentication.\n"
            "\n"
            "  Usage:\n"
            "\tRun under root privilege, usually by `sudo', with \n"
            "\targuments shown below.\n\n"
            "  Necessary Arguments:\n\n"
            "\t-u, --username           Your username.\n"
            "\t-p, --password           Your password.\n"
            "\t-g, --gateway            Your Gateway Server Address.\n"
            "\t-d, --dns                Your DNS Server Address.\n"
            "\n"
            "  Optional Arguments:\n\n"
            "\t--device                 Specify which device to use.\n"
            "\t                         Default is usually eth0.\n\n"
            "\t--dhcp                   Use this if your ISP requests.\n"
            "\t                         You may need to run `dhclient' manualy\n"
            "\t                           after successful authentication.\n\n"
            "\t-b, --background         Program fork background after initializtion.\n\n"
            "\t-h, --help               Show this help.\n\n"
            "\n\n"
            "  About ZDC Client:\n\n"
            "\tThis program is a C implementation to DigiChina Authentication.\n"
            "\tBy refering another Java program called `scut_supplicant', ZDC is\n"
            "\t more light-weight. But the protocol research done by Yaoqi and \n"
            "\tsome others was important to ZDC, greate thanks to them.\n\n"
            
            "\tZDC Client is a software developed individually, with NO relation\n"
            "\t-ship to do with Digital China company.\n\n\n"
            
            "\tAnother PT work. Blog: http://apt-blog.co.cc\n"
            "\t\t\t\t\t\t\t2009.05.18\n"
            );
}

/* calcuate for md5 digest */
char* 
md5digest(const char* str, size_t len)
{
	md5_state_t state;
	md5_byte_t digest[16];
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)str, len);
	md5_finish(&state, digest);

    char *result = malloc(16);
    memcpy(result, digest, 16);
    return result;
}

enum EAPType 
get_eap_type(u_char type, u_char reqType) 
{
    switch(type){
        case 0x01:
            switch(reqType){
                case 0x01:
                    return EAP_REQUEST_IDENTITY;
                case 0x04:
                    return EAP_REQUETS_MD5_CHALLENGE;
            }
            break;
        case 0x03:
            return EAP_SUCCESS;
        case 0x04:
            return EAP_FAILURE;
    }
    fprintf(stderr, "Error Package Type and TypeReq: %d %d\n", type, reqType);
    return ERROR;
}

void 
action_by_eap_type(enum EAPType pType, 
                        const struct sniff_eap_header *header) {
//    printf("PackType: %d\n", pType);
    switch(pType){
        case EAP_SUCCESS:
            state = ONLINE;
            printf("##Protocol: EAP_SUCCESS\n");
            fprintf(stderr, "&&Info: Authorized Access to Network. \n");
            break;
        case EAP_FAILURE:
            state = READY;
            printf("##Protocol: EAP_FAILURE\n");
            if(state == ONLINE){
                fprintf(stderr, "&&Info: SERVER Forced Logoff\n");
            } else {
                fprintf(stderr, "&&Info: Invalid Username or Password. \n");
            }
            pcap_breakloop (handle);
            break;
        case EAP_REQUEST_IDENTITY:
            if (state == ONLINE){
                printf("##Protocol: REQUEST EAP-Identity - Keep Alive %d\n", 
                                            live_count++);
            }
            else if (state == STARTED){
                printf("##Protocol: REQUEST EAP-Identity\n");
            }
            send_eap_packet(EAP_RESPONSE_IDENTITY);
            break;
        case EAP_REQUETS_MD5_CHALLENGE:
            state = ID_AUTHED;
            printf("##Protocol: REQUEST MD5-Challenge(PASSWORD)\n");
            fill_password_md5((u_char*)header->eap_md5_challenge);
            send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
        default:
            return;
    }
}

void 
send_eap_packet(enum EAPType send_type)
{
    u_char *frame_data;
    int     frame_length;
    switch(send_type){
        case EAPOL_START:
            state = STARTED;
            frame_data= eapol_start;
            frame_length = 14 + 4;
            printf("##Protocol: SEND EAPOL-Start\n");
            break;
        case EAPOL_LOGOFF:
            state = READY;
            frame_data = eapol_logoff;
            frame_length = 14 + 4;
            printf("##Protocol: SEND EAPOL-Logoff\n");
            break;
        case EAP_RESPONSE_IDENTITY:
            frame_data = eap_response_ident;
            frame_length = 14 + 9 + username_length + 46;
            printf("##Protocol: SEND EAP-Response/Identity\n");
            break;
        case EAP_RESPONSE_MD5_CHALLENGE:
            frame_data = eap_response_md5ch;
            frame_length = 14 + 10 + 16 + username_length + 46;
            printf("##Protocol: SEND EAP-Response/Md5-Challenge\n");
            break;
        default:
            fprintf(stderr,"ERROR: Wrong Send Request Type.\n");
            return;
    }
    if (pcap_sendpacket(handle, frame_data, frame_length) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        return;
    }
}

/* Callback function for pcap.  */
void
get_packet(u_char *args, const struct pcap_pkthdr *header, 
    const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_eap_header *eap_header;

    ethernet = (struct sniff_ethernet*)(packet);
    eap_header = (struct sniff_eap_header *)(packet + SIZE_ETHERNET);

    enum EAPType p_type = get_eap_type(eap_header->eap_t, 
                                               eap_header->eap_op);
    action_by_eap_type(p_type, eap_header);
    return;
}

void init_frames()
{
    u_char *local_info = malloc(46);
    int data_index;

    /* *  local_info segment used by both RES/Idn and RES/MD5 frame * */
    data_index = 0;
    local_info[data_index++] = dhcp_on;
    memcpy(local_info + data_index, &local_ip, 4);
    data_index += 4;
    memcpy(local_info + data_index, &local_mask, 4);
    data_index += 4;
    memcpy(local_info + data_index, &local_gateway, 4);
    data_index += 4;
    memcpy(local_info + data_index, &local_dns, 4);
    data_index += 4;
    char* username_md5 = md5digest(username, username_length);
    memcpy(local_info + data_index, username_md5, 16);
    data_index += 16;
    free(username_md5);
    memcpy(local_info + data_index, client_ver, 13);


    /*****  EAPOL Header  *******/
    u_char eapol_header[SIZE_ETHERNET];
    data_index = 0;
    u_short eapol_t = htons (0x888e);
    memcpy (eapol_header + data_index, muticast_mac, 6); /* dst addr. muticast */
    data_index += 6;
    memcpy (eapol_header + data_index, local_mac, 6);    /* src addr. local mac */
    data_index += 6;
    memcpy (eapol_header + data_index, &eapol_t, 2);    /*  frame type, 0x888e*/

    /**** EAPol START ****/
    u_char start_data[4] = {0x01, 0x01, 0x00, 0x00};
    memcpy (eapol_start, eapol_header, 14);
    memcpy (eapol_start + 14, start_data, 4);

    /****EAPol LOGOFF ****/
    u_char logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
    memcpy (eapol_logoff, eapol_header, 14);
    memcpy (eapol_logoff + 14, logoff_data, 4);


    /* EAP RESPONSE IDENTITY */
    u_char eap_resp_iden_head[9] = {0x01, 0x00, 
                                    0x00, 5 + 46 + username_length,  /* eapol_length */
                                    0x02, 0x01, 
                                    0x00, 5 + username_length,       /* eap_length */
                                    0x01};
    
    eap_response_ident = malloc (14 + 9 + 46 + username_length);

    data_index = 0;
    memcpy (eap_response_ident + data_index, eapol_header, 14);
    data_index += 14;
    memcpy (eap_response_ident + data_index, eap_resp_iden_head, 9);
    data_index += 9;
    memcpy (eap_response_ident + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_ident + data_index, local_info, 46);

    /** EAP RESPONSE MD5 Challenge **/
    u_char eap_resp_md5_head[10] = {0x01, 0x00, 
                                   0x00, 6 + 16 + username_length + 46, /* eapol-length */
                                   0x02, 0x02, 
                                   0x00, 6 + 16 + username_length, /* eap-length */
                                   0x04, 0x10};
    eap_response_md5ch = malloc (14 + 4 + 6 + 16 + username_length + 46);

    data_index = 0;
    memcpy (eap_response_md5ch + data_index, eapol_header, 14);
    data_index += 14;
    memcpy (eap_response_md5ch + data_index, eap_resp_md5_head, 10);
    data_index += 26;// 剩余16位在收到REQ/MD5报文后由fill_password_md5填充 
    memcpy (eap_response_md5ch + data_index, username, username_length);
    data_index += username_length;
    memcpy (eap_response_md5ch + data_index, local_info, 46);
}

void 
fill_password_md5(u_char attach_key[])
{
    char *psw_key = malloc(1 + password_length + 16);
    char *md5_challenge_key;
    psw_key[0] = 0x02;
    memcpy (psw_key + 1, password, password_length);
    memcpy (psw_key + 1 + password_length, attach_key, 16);

    md5_challenge_key = md5digest(psw_key, 1 + password_length + 16);
    memcpy (eap_response_md5ch + 14 + 10, md5_challenge_key, 16);

    free (psw_key);
    free (md5_challenge_key);
}

void init_info()
{
    if(gateway != NULL)
        local_gateway = inet_addr(gateway);
    if(dns != NULL)  
        local_dns = inet_addr(dns);
    if(username == NULL || password == NULL){
        fprintf (stderr,"Error: Username or Password not promoted.\n"
                        "  type ZDC_Client --help for usage.\n");
        exit(1);
    }

    if (local_gateway == -1 || local_dns == -1) {
        fprintf (stderr,"Error: Gateway or DNS address not promoted or format error.\n"
                        "  type ZDC_Client --help for usage.\n");

        exit(1);
    }

    username_length = strlen(username);
    password_length = strlen(password);

    if (background){
        pid_t pID = fork();
        if (pID != 0) {
            fprintf(stderr, "&&Info: ZDC Forked background.\nPID:[%d]\n", pID);
            exit(0);
        }
    }

}

void init_device()
{
    struct bpf_program fp;			/* compiled filter program (expression) */
    char filter_exp[] = "ether proto 0x888e";/* filter expression [3] */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

    if(dev == NULL)
	    dev = pcap_lookupdev(errbuf);

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",
			errbuf);
		exit(EXIT_FAILURE);
    }
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "ERROR: %s: %s\n",
		    dev, errbuf);
        exit(EXIT_FAILURE);
	}



	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
    pcap_freecode(&fp);


    struct ifreq ifr;
    int sock;

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    strcpy(ifr.ifr_name, dev);

    //获得网卡Mac
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

    //获得IP
    if(ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    local_ip = ((struct  sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;

    //获得IP掩码
    if(ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    local_mask = ((struct sockaddr_in*)&ifr.ifr_netmask)->sin_addr.s_addr;
}

static void
signal_interrupted (int signo)
{
    printf("\nUSER Interrupted. \n");
    pcap_breakloop (handle);
}

int main(int argc, char **argv)
{
    int c;
    while (1) {

        /* getopt_long stores the option index here. */
        int option_index = 0;
        c = getopt_long (argc, argv, "u:p:g:d:hb",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 0:
                 break;
            case 'b':
                background = 1;
                break;
            case 2:
                dev = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 'g':
                gateway = optarg;
                break;
            case 'd':
                dns = optarg;
                break;
            case 'h':
                show_usage();
                exit(0);
                break;
            case '?':
                show_usage();
                if (optopt == 'u' || optopt == 'p'|| optopt == 'g'|| optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                return 1;
                break;
            default:
                fprintf (stderr,"Unknown option character `\\x%x'.\n", c);
                return 1;
        }
    }
    init_info();
    init_device();
    signal (SIGINT, signal_interrupted);
    signal (SIGTERM, signal_interrupted);    

    printf("######## Device Info. #########\n");
    printf("Device:   %s\n", dev);
    printf("MAC:      ");
    print_hex(local_mac, 6);
    printf("IP:       %s\n", inet_ntoa(*(struct in_addr*)&local_ip));
    printf("MASK:     %s\n", inet_ntoa(*(struct in_addr*)&local_mask));
    printf("Gateway:  %s\n", inet_ntoa(*(struct in_addr*)&local_gateway));
    printf("DNS:      %s\n", inet_ntoa(*(struct in_addr*)&local_dns));
    printf("###############################\n");

    init_frames();
    send_eap_packet(EAPOL_LOGOFF);
    send_eap_packet(EAPOL_START);

	pcap_loop(handle, -1, get_packet, NULL);

    send_eap_packet(EAPOL_LOGOFF);
	pcap_close(handle);
    free (eap_response_ident);
    free (eap_response_md5ch);
    return 0;
}

