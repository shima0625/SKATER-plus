#pragma once
#include <stddef.h>
typedef struct TestCurl CURL;
typedef int CURLcode; typedef long long curl_off_t;
struct curl_blob { void *data; size_t len; unsigned int flags; };
#define CURL_BLOB_NOCOPY 0
#define CURLE_OK 0
#define CURLE_FAILED_INIT 2
#define CURL_GLOBAL_DEFAULT 0
enum { CURLOPT_URL=1,CURLOPT_USERAGENT,CURLOPT_CAINFO,CURLOPT_SSL_VERIFYPEER,
CURLOPT_SSL_VERIFYHOST,CURLOPT_PROTOCOLS_STR,CURLOPT_REDIR_PROTOCOLS_STR,
CURLOPT_FOLLOWLOCATION,CURLOPT_MAXREDIRS,CURLOPT_CONNECTTIMEOUT,CURLOPT_TIMEOUT,
CURLOPT_LOW_SPEED_LIMIT,CURLOPT_LOW_SPEED_TIME,CURLOPT_FAILONERROR,CURLOPT_WRITEFUNCTION,
CURLOPT_WRITEDATA,CURLOPT_XFERINFOFUNCTION,CURLOPT_NOPROGRESS,CURLINFO_RESPONSE_CODE,
CURLOPT_CAINFO_BLOB,CURLOPT_XFERINFODATA };
#define CURLOPT_NOBODY 100
#define CURLINFO_REDIRECT_URL 101
#define CURLINFO_NAMELOOKUP_TIME 102
#define CURLINFO_CONNECT_TIME 103
#define CURLINFO_APPCONNECT_TIME 104
#define CURLINFO_STARTTRANSFER_TIME 105
#define CURLINFO_TOTAL_TIME 106
CURL *curl_easy_init(void);
void curl_easy_reset(CURL *);
void curl_easy_cleanup(CURL *);
CURLcode curl_easy_setopt(CURL *,int,...);
CURLcode curl_easy_perform(CURL *);
CURLcode curl_easy_getinfo(CURL *,int,...);
CURLcode curl_global_init(long); void curl_global_cleanup(void);
typedef struct TestMulti CURLM;
typedef int CURLMcode;
#define CURLM_OK 0
#define CURLMSG_DONE 1
typedef struct { int msg; union { CURLcode result; } data; } CURLMsg;
CURLM *curl_multi_init(void);
CURLMcode curl_multi_add_handle(CURLM *,CURL *);
CURLMcode curl_multi_remove_handle(CURLM *,CURL *);
CURLMcode curl_multi_perform(CURLM *,int *);
CURLMcode curl_multi_poll(CURLM *,void *,unsigned,int,int *);
CURLMsg *curl_multi_info_read(CURLM *,int *);
CURLMcode curl_multi_cleanup(CURLM *);
