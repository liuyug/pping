
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <curl/curl.h>

#include "pping.h"

int ftp_datalen;

size_t ftp_handle_default(void *ptr, size_t size, size_t nmemb, void * stream)
{
#if 0
    char * buf = (char *)ptr;
    printf("%s",buf);
#endif
    ftp_datalen += (size * nmemb);
    return size * nmemb;
}

int ftp_ping(const char * url)
{
    int ret;
    CURL * handle = curl_easy_init();
#if 0
    curl_easy_setopt(handle, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(handle, CURLOPT_HEADERFUNCTION, ftp_handle_default);
    curl_easy_setopt(handle, CURLOPT_USERNAME, "anonymous");
    curl_easy_setopt(handle, CURLOPT_PASSWORD, "ftp@pping.com");
#endif
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, ftp_handle_default);
    curl_easy_setopt(handle, CURLOPT_URL, url);
    char s_url[80];
    compact_url(url, s_url);
    if(!ping_quiet){
        printf("ftp ping: %s\n", s_url);
    }
    int seq = 0;
    double rtt_time;
    struct timeval watchtv, tv;
    while(1){
        ftp_datalen = 0;
        gettimeofday(&watchtv,NULL);
        rtt_sentpkg++;
        seq++;
        ret = curl_easy_perform(handle);
        if(ret!=CURLE_OK){
            errno=ret;
            if(!ping_quiet){
                perror("curl");
            }
            if(ping_count>0&&seq>=ping_count)
                return ret;
            ppingsleep(ping_interval);
            continue;
        }
        gettimeofday(&tv,NULL);
        rtt_time=(tv.tv_sec-watchtv.tv_sec)*1000+(double)(tv.tv_usec-watchtv.tv_usec)/1000;
        if(!ping_quiet){
            printf("%d bytes from %s: seq=%d time=%.1f ms\n",
                    ftp_datalen, s_url ,seq, rtt_time
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
        if(ping_count>0&&seq>=ping_count)
            break;
        ppingsleep(ping_interval);
    }
    curl_easy_cleanup(handle);
    return ret;
}

