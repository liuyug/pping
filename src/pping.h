#ifndef _PPING_H_
#define _PPING_H_

#include <errno.h>
#include <string.h>

#define LEFT    0x0001
#define RIGHT   0x0002
#define BOTH    LEFT | RIGHT

extern int timeout;
extern double rtt_min;
extern double rtt_max;
extern double rtt_sum;
extern unsigned int rtt_sentpkg;
extern unsigned int rtt_recvpkg;
extern unsigned int ping_count;
extern unsigned int ping_interval;
extern int          ping_stat;
extern int          ping_quiet;

#define max(a,b) ((a)>(b)?(a):(b))
#define min(a,b) ((a)<(b)?(a):(b))

#ifdef __WIN32__
#define WINVER 0x600
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define SOCKET int
#define INVALID_SOCKET -1
#endif

#define MAXBUF  10240
#define MAXURL  1024

#ifdef __WIN32__
#define ppingerror(x)  fprintf(stderr,"%s:%s:%d\n\n",__FUNCTION__,x,WSAGetLastError())
#else
#define ppingerror(x)  fprintf(stderr,"%s:%s:%s\n\n",__FUNCTION__,x,strerror(errno))
#endif

#ifdef __WIN32__
#define ppingsleep(x)  Sleep(x)
#else
#define ppingsleep(x)  sleep((unsigned int)(x/1000))
#endif

#ifdef __WIN32__
#define ppingclose(x)  closesocket(x)
#else
#define ppingclose(x)  close(x)
#endif

char * ms2s(unsigned int byte, char * buf);
const char * compact_url(const char * url, char buf[80]);
int icmp_ping(const char * hostname,unsigned int datalen);
int http_ping(const char * url);
int ftp_ping(const char * url);
#endif
