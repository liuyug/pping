#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

#include "pping.h"

#define VERSION "v1.1.6"

int timeout=5;
double rtt_min;
double rtt_max;
double rtt_sum;
unsigned int rtt_sentpkg;
unsigned int rtt_recvpkg;
int          ping_mode;
int          ping_stat;
int          ping_quiet;
unsigned int ping_count;
unsigned int ping_interval;
unsigned int ping_packetsize;
char ping_hostname[MAXURL];
char ping_url[MAXURL];


enum {
    AUTO_PING,
    ICMP_PING,
    HTTP_PING,
    FTP_PING
};

char * ms2s(unsigned int byte, char * buf)
{
    if (byte == 0){
        sprintf(buf,"N/A");
    } else if (byte < 1000){
        sprintf(buf,"%3dms", byte);
    } else {
        double bb = byte;
        bb = bb / 1000;
        sprintf(buf,"%4.1fs", bb);
    } 
    return buf;
}

char *trim(char *str,int from,const char *chs)
{
    char *p, *chstr;
    int len=strlen(str);
    p=str;
    if(len==0)   return str;
    chstr=str+len-1;
    if(from&RIGHT){
        while(chstr>=str&&strchr(chs,*chstr)!=NULL) chstr--;
        chstr++;
        *chstr='\0';
        len = chstr - p;
    }
    chstr=str;
    if(from&LEFT){
        while(*chstr!='\0'&&strchr(chs,*chstr)!=NULL) chstr++;
        if(str!=chstr){
            for(int i=chstr-p;i<len;i++){
                *p++=*chstr++;
            }
            *p='\0';
        }
    }
    return str;
}

const char * compact_url(const char * url, char buf[80])
{
    if(url==NULL)  return NULL;
    int len = strlen(url);
    int i = 0;
    if(len > 32){
        for(; i<29 ; i++)
            buf[i]=url[i];
        buf[i++]='.';
        buf[i++]='.';
        buf[i++]='.';
    } else {
        for(; i<len ; i++)
            buf[i]=url[i];
        for(;i<32;i++)
            buf[i]=' ';
    }
    buf[32]=' ';
    buf[33]='\0';
    return buf;
} 

int output_url(const char * url)
{
    char buf[80];
    printf("%s", compact_url(url, buf));
    fflush(stdout);
    return 0;
}

void ping_summmary(const char * hostname)
{
    char min_buf[16], avg_buf[16], max_buf[16];
    if(ping_stat==1){
        printf("| %4d | %4d | %3d%% | %s | %s | %s |\n",
                rtt_sentpkg,
                rtt_recvpkg,
                (rtt_sentpkg-rtt_recvpkg)*100/rtt_sentpkg,
                ms2s(rtt_min,min_buf),
                ms2s(rtt_recvpkg>0?rtt_sum/rtt_recvpkg:rtt_sum, avg_buf),
                ms2s(rtt_max, max_buf)
                );
    }else{
        printf("\n");
        printf("--- %s ping statistics ---\n",hostname);
        printf("%d packets transmitted, %d received, %d%% packet loss\n",
               rtt_sentpkg,rtt_recvpkg,(rtt_sentpkg-rtt_recvpkg)*100/rtt_sentpkg);
        printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
               rtt_min,rtt_recvpkg>0?rtt_sum/rtt_recvpkg:rtt_sum,rtt_max);
    }

}
void ping_sighandler(int sig)
{
    ping_summmary(ping_hostname);
    curl_global_cleanup();
    exit(0);
}
int ping_proto(const char * url)
{
    int automode;
    char *pos;
    if(strncasecmp(url,"ftp://",6)==0){
        automode=FTP_PING;
        strcpy(ping_hostname,url+6);
        pos=strchr(ping_hostname,'/');
        if(pos!=NULL)   *pos='\0';
        pos=strchr(ping_hostname,'@');
        if(pos!=NULL)   strcpy(ping_hostname,pos+1);
    }else if(strncasecmp(url,"http://",7)==0){
        automode=HTTP_PING;
        strcpy(ping_hostname,url+7);
        pos=strchr(ping_hostname,'/');
        if(pos!=NULL)   *pos='\0';
        pos=strchr(ping_hostname,':');
        if(pos!=NULL)   *pos='\0';
    }else{
        automode=ICMP_PING;
        strcpy(ping_hostname,url);
    }
    if(ping_mode!=AUTO_PING) automode=ping_mode;
    if(ping_stat > 0)
        output_url(url);

    rtt_sum=rtt_min=rtt_max=rtt_sentpkg=rtt_recvpkg=0;
    if(automode==ICMP_PING){
        if(icmp_ping(ping_hostname,ping_packetsize)==0)
            ping_summmary(ping_hostname);
        else
            perror("");
    }else if(automode==HTTP_PING){
        if(http_ping(url)==0)
            ping_summmary(ping_hostname);
        else
            perror("");
    }else if(automode==FTP_PING){
        if(ftp_ping(url)==0)
            ping_summmary(ping_hostname);
        else
            perror("");
    }
    return 0;
}
int ping_fromstdin()
{
    char url[MAXURL];
    while(1){
        fgets(url,MAXURL,stdin);
        if(feof(stdin)) break;
        trim(url,BOTH," \t\n\r");
        if(url[0]!='\0'&&url[0]!='#'){
            ping_proto(url);
        }
    }
    return 0;
}
/*************************************************************
NOTE: In Window platform must have Administrator privilege.
*************************************************************/
void appinfo()
{
    printf(""
"PPing "VERSION"\n"
"(C) 2012 Liu Yugang <liuyug@gmail.com>\n"
           "\n");
}
void usage()
{
    printf(""
"Usage: pping [OPTION...] <[hostname] or [url]>\n"
"Common options:\n"
"   -h               print this message\n"
"   -c <count>       how many times to ping\n"
"   -i <interval>    delay between each ping, default 1 sec\n"
"      --icmp        force pinging with ICMP\n"
"      --http        force pinging with HTTP\n"
"      --ftp         force pinging with FTP\n"
"      --stat        statistics simply\n"
"      --quiet       quiet mode\n"
"\n"
"ICMP options:\n"
"   -s <packetsize>  how many data bytes to be sent, maximum 10232\n"
"\n"
"Note:\n"
"When hostname or url is '-', read standard input.\n"
    "");
    return ;
}

int main(int argc,char *argv[])
{
    // default value
    ping_count=0;
    ping_interval=1000;
    ping_packetsize=56;
    ping_quiet=0;
    ping_stat=0;
    ping_mode=AUTO_PING;
    // parse command argument
    int opt;
    int option_index = 0;
    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"icmp", no_argument, &ping_mode, ICMP_PING},
        {"http", no_argument, &ping_mode, HTTP_PING},
        {"ftp", no_argument, &ping_mode, FTP_PING},
        {"stat", no_argument, &ping_stat, 1},
        {"quiet", no_argument, &ping_quiet, 1},
        {0, 0, 0, 0}
    };
    if(argc<2){
        appinfo();
        usage();
        return 1;
    }
    while ((opt = getopt_long(argc, argv, "hqp:c:i:s:",long_options,&option_index)) != -1)
    {
        switch (opt)
        {
        case 0:
            break;
        case 'h':
            appinfo();
            usage();
            return 0;
        case 'q':
            ping_quiet=1;
            break;
        case 'c':
            ping_count=atoi(optarg);
            break;
        case 'i':
            ping_interval=atoi(optarg);
            break;
        case 's':
            ping_packetsize=atoi(optarg);
            break;
        case '?':
            printf("\nTry 'pping --help' for more options.\n");
            return 1;
        default:
            appinfo();
            usage();
            return 1;
        }
    }
    if(optind >= argc){
        appinfo();
        usage();
        return 1;
    }
#ifdef __WIN32__
    WSADATA wsaData;
    if(WSAStartup(MAKEWORD(2,2), &wsaData)!=0){
        ppingerror("WSAStartup");
    };
#endif
    curl_global_init(CURL_GLOBAL_ALL);
    signal(SIGINT,ping_sighandler);
    if(ping_stat > 0) {
        if(ping_count == 0) ping_count = 4;
        ping_quiet = 1;
        printf("%34c sent | recv | loss |  min  |  avg  |  max  |\n",'|');
    }
    while(optind < argc){
        strcpy(ping_url,argv[optind++]);
        if(strcmp(ping_url,"-")==0){
            ping_fromstdin();
        }else{
            ping_proto(ping_url);
        }
    }
    curl_global_cleanup();
#ifdef __WIN32__
    WSACleanup();
#endif
    return 0;
}
