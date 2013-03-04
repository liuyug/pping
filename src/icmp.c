#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<sys/time.h>

#include "pping.h"

#ifdef __WIN32__
#define ICMP_ECHOREPLY          0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH       3       /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH      4       /* Source Quench                */
#define ICMP_REDIRECT           5       /* Redirect (change route)      */
#define ICMP_ECHO               8       /* Echo Request                 */
#define ICMP_TIME_EXCEEDED      11      /* Time Exceeded                */
#define ICMP_PARAMETERPROB      12      /* Parameter Problem            */
#define ICMP_TIMESTAMP          13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY     14      /* Timestamp Reply              */
#define ICMP_INFO_REQUEST       15      /* Information Request          */
#define ICMP_INFO_REPLY         16      /* Information Reply            */
#define ICMP_ADDRESS            17      /* Address Mask Request         */
#define ICMP_ADDRESSREPLY       18      /* Address Mask Reply           */
#define NR_ICMP_TYPES           18


typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

struct ip {
//#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
//#endif
//#if __BYTE_ORDER == __BIG_ENDIAN
//    unsigned int ip_v:4;                /* version */
//    unsigned int ip_hl:4;               /* header length */
//#endif
    u_int8_t ip_tos;                    /* type of service */
    u_short ip_len;                     /* total length */
    u_short ip_id;                      /* identification */
    u_short ip_off;                     /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    u_int8_t ip_ttl;                    /* time to live */
    u_int8_t ip_p;                      /* protocol */
    u_short ip_sum;                     /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
};
struct icmp_ra_addr {
    u_int32_t ira_addr;
    u_int32_t ira_preference;
};

struct icmp {
    u_int8_t  icmp_type;  /* type of message, see below */
    u_int8_t  icmp_code;  /* type sub code */
    u_int16_t icmp_cksum; /* ones complement checksum of struct */
    union {
        u_char ih_pptr;             /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;   /* gateway address */
        struct ih_idseq {           /* echo datagram */
            u_int16_t icd_id;
            u_int16_t icd_seq;
        } ih_idseq;
        u_int32_t ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu {
            u_int16_t ipm_void;
            u_int16_t ipm_nextmtu;
        } ih_pmtu;
        struct ih_rtradv {
            u_int8_t irt_num_addrs;
            u_int8_t irt_wpa;
            u_int16_t irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
    union {
        struct {
            u_int32_t its_otime;    /* Originate Timestamp */
            u_int32_t its_rtime;    /* Receive Timestamp   */
            u_int32_t its_ttime;    /* Transmit Timestamp  */
        } id_ts;
        struct {
            struct ip idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        struct icmp_ra_addr id_radv;
        u_int32_t   id_mask;
        u_int8_t    id_data[1];
    } icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};
#endif


struct timeval watchtv;

int icmp_recv(SOCKET s,unsigned int seq,unsigned char *data,unsigned int datalen)
{
    struct icmp *icmp;
    struct ip *ip;
    int readbytes,iplen;
    unsigned char recvbuf[MAXBUF];
    struct timeval tv;
    double rtt_time;
    while(1){
        memset(&recvbuf,0,MAXBUF);
        readbytes=recv(s,recvbuf,MAXBUF,0);
        gettimeofday(&tv,NULL);
        rtt_time=(tv.tv_sec-watchtv.tv_sec)*1000+(double)(tv.tv_usec-watchtv.tv_usec)/1000;
        if(readbytes>0){
            ip=(struct ip *)recvbuf;
            iplen=ip->ip_hl<<2;
            icmp=(struct icmp *)(recvbuf+iplen);
            if(icmp->icmp_type==ICMP_ECHOREPLY
                    &&icmp->icmp_seq==seq
                    &&icmp->icmp_id==getpid()
                    &&memcmp(icmp->icmp_data,data,datalen)==0
               ) {
                if(!ping_quiet){
                    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n",
                           datalen,inet_ntoa(ip->ip_src),icmp->icmp_seq,ip->ip_ttl,rtt_time
                           );
                }
                if(rtt_min==0){
                    rtt_min=max(rtt_min,rtt_time);
                }else{
                    rtt_min=min(rtt_min,rtt_time);
                }
                rtt_max=max(rtt_max,rtt_time);
                rtt_sum+=rtt_time;
                rtt_recvpkg++;
            }else{
                continue;   // it's not my packet, skip.
            }
        }else{
            if(!ping_quiet){
                printf("timeout.\n");
            }
        }
        break;
    }
    return 0;
}

int icmp_send(SOCKET s,unsigned int seq,unsigned char *data,unsigned int datalen)
{
    struct icmp *icmp;
    unsigned short *sumbuf,cksum;
    char sendbuf[MAXBUF];
    int sum=0,len,nleft;
    int sentbytes;
    memset(&sendbuf,0,sizeof(sendbuf));
    icmp=(struct icmp *)sendbuf;
    icmp->icmp_type=ICMP_ECHO;
    icmp->icmp_code=0;
    icmp->icmp_cksum=0;
    icmp->icmp_id=getpid();
    icmp->icmp_seq=seq;
    memcpy(icmp->icmp_data,data,datalen);
    len=8/* icmp head */+datalen;
    nleft=len;
    sumbuf=(unsigned short *)sendbuf;
    while(nleft>1) {
        sum+=*sumbuf++;
        nleft-=2; /* nleft is the byte number */
    }
    if(nleft==1) {
        *(unsigned char *)&(cksum)=*(unsigned char *)sumbuf;
        sum+=cksum;
    }
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    cksum=~sum;
    icmp->icmp_cksum=cksum;
    gettimeofday(&watchtv,NULL);
    sentbytes=send(s,sendbuf,len,0);
    if(sentbytes>0){
        rtt_sentpkg++;
        return 0;
    }
    return 1;
}
/*************************************************************

Pinging 9.181.2.72 with 32 bytes of data:

Reply from 9.181.2.72: bytes=32 time=22ms TTL=249
Reply from 9.181.2.72: bytes=32 time=16ms TTL=249
Reply from 9.181.2.72: bytes=32 time=16ms TTL=249
Reply from 9.181.2.72: bytes=32 time=16ms TTL=249

Ping statistics for 9.181.2.72:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 16ms, Maximum = 22ms, Average = 17ms

PING 9.181.2.72 (9.181.2.72) 56(84) bytes of data.
64 bytes from 9.181.2.72: icmp_req=1 ttl=249 time=16.8 ms
64 bytes from 9.181.2.72: icmp_req=2 ttl=249 time=18.1 ms
^C
--- 9.181.2.72 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 16.875/17.506/18.137/0.631 ms

*************************************************************/

int icmp_ping(const char * hostname,unsigned int datalen)
{
    SOCKET s;
    unsigned int seq;
    struct hostent *hp;
    unsigned char *data;
    // In window platform must have administrator privilege.
    s=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(s==INVALID_SOCKET){
        if(errno == EPERM){
            fprintf(stderr,"Please use root privilege to ping!\n\n");
        }else{
            ppingerror("socket");
        }
        return 1;
    }

#ifdef __WIN32__
    unsigned int optval;
    optval=5000;
    if(setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char *)&optval,sizeof(optval))!=0){
        ppingerror("setsockopt");
        return 1;
    };
#else
    struct timeval to;
    to.tv_sec=5;
    to.tv_usec=0;
    if(setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(void *)&to,sizeof(to))!=0){
        ppingerror("setsockopt");
        return 1;
    };
#endif

    struct sockaddr_in din;
    memset(&din,0,sizeof(din));
    din.sin_family=AF_INET;
    if((hp=gethostbyname(hostname))!=NULL) {
        memcpy(&din.sin_addr,hp->h_addr_list[0],hp->h_length);
    }else{
        fprintf(stderr,"Can't find the server at %s\n",hostname);
        return 1;
    }
    /* printf("ICMP PING %s (%s) ",hostname,inet_ntoa(din.sin_addr)); */

    if(connect(s,(struct sockaddr *)&din,sizeof(din))!=0){
        ppingerror("connect");
        return 1;
    };
#if 0
    struct sockaddr_in sin;
    memset(&sin,0,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=INADDR_ANY;
    if(bind(s,(struct sockaddr *)&sin,sizeof(sin))!=0){
        ppingerror("bind");
        return 1;
    };
#endif
    seq=1;
    data=malloc(sizeof(char)*datalen);
    memset(data,'a',datalen);

    if(!ping_quiet)
        printf("icmp ping %s with %d bytes of data:\n", hostname, datalen);
    while(1) {
        icmp_send(s,seq,data,datalen);
        icmp_recv(s,seq,data,datalen);
        seq++;
        if(ping_count>0&&seq>ping_count)
            break;
        ppingsleep(ping_interval);
    }
    free(data);
    ppingclose(s);
    return 0;
}


