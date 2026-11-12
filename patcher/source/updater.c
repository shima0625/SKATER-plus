#include <3ds.h>
#include <curl/curl.h>
#include <errno.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "updater.h"
#include "update_manifest.h"
#include "sha256.h"

#define UPDATE_DIR "sdmc:/3ds/skater-plus-patcher"
#define STAGED UPDATE_DIR "/update.tmp"
#define RELEASES "https://github.com/shima0625/SKATER-plus/releases/"
#define OWN_TITLE UINT64_C(0x000400000F5A5400)

typedef struct { FILE *file; char *memory; size_t size,limit; Sha256 hash; } Download;
static const char *last_check="Not checked";
const char *updater_status(void) { return last_check; }
#ifdef SKATER_UPDATE_TIMINGS
static u64 check_start;
#endif

typedef struct { void *soc; unsigned stage; } Network;
static void network_close(Network *n) {
    if (n->stage>=4) curl_global_cleanup();
    if (n->stage>=3) sslcExit();
    if (n->stage>=2) socExit();
    free(n->soc); n->soc=NULL; n->stage=0;
}
static int network_open(Network *n) {
    n->soc=memalign(0x1000,0x100000);
    if (!n->soc) return -1;
    n->stage=1;
    if (R_FAILED(socInit(n->soc,0x100000))) goto fail;
    n->stage=2;
    if (R_FAILED(sslcInit(0))) goto fail;
    n->stage=3;
    u8 entropy[32];
    if (R_FAILED(sslcGenerateRandomData(entropy,sizeof(entropy)))) goto fail;
    if (curl_global_init(CURL_GLOBAL_DEFAULT)!=CURLE_OK) goto fail;
    n->stage=4; return 0;
fail: network_close(n); return -1;
}

static size_t receive(char *ptr,size_t size,size_t count,void *user) {
    Download *d=user;
    if (size && count>SIZE_MAX/size) return 0;
    size_t n=size*count;
    if (n>d->limit-d->size) return 0;
    if (d->file && fwrite(ptr,1,n,d->file)!=n) return 0;
    if (d->memory) memcpy(d->memory+d->size,ptr,n);
    sha256_update(&d->hash,ptr,n); d->size+=n; return n;
}

static int progress(void *user,curl_off_t total,curl_off_t now,curl_off_t up_total,curl_off_t up_now) {
    (void)user; (void)total; (void)now; (void)up_total; (void)up_now;
    hidScanInput(); return !aptMainLoop() || (hidKeysDown()&KEY_B);
}

static int configure(CURL *curl,const char *url,Download *d,bool head) {
    /* Reset options but preserve the connection and TLS session caches. */
    curl_easy_reset(curl);
#define SETOPT(option,value) do { if (curl_easy_setopt(curl,option,value)!=CURLE_OK) return -1; } while (0)
    SETOPT(CURLOPT_URL,url);
    SETOPT(CURLOPT_USERAGENT,"SKATER-plus/" SKATER_VERSION);
    SETOPT(CURLOPT_CAINFO,"romfs:/assets/updater-ca.pem");
    SETOPT(CURLOPT_SSL_VERIFYPEER,1L);
    SETOPT(CURLOPT_SSL_VERIFYHOST,2L);
    SETOPT(CURLOPT_PROTOCOLS_STR,"https");
    SETOPT(CURLOPT_REDIR_PROTOCOLS_STR,"https");
    SETOPT(CURLOPT_NOBODY,head?1L:0L);
    SETOPT(CURLOPT_FOLLOWLOCATION,head?0L:1L);
    SETOPT(CURLOPT_MAXREDIRS,5L);
    SETOPT(CURLOPT_CONNECTTIMEOUT,head || d->memory?4L:8L);
    SETOPT(CURLOPT_TIMEOUT,head || d->memory?6L:90L);
    SETOPT(CURLOPT_LOW_SPEED_LIMIT,128L);
    SETOPT(CURLOPT_LOW_SPEED_TIME,15L);
    SETOPT(CURLOPT_FAILONERROR,1L);
    SETOPT(CURLOPT_WRITEFUNCTION,receive);
    SETOPT(CURLOPT_WRITEDATA,d);
    SETOPT(CURLOPT_XFERINFOFUNCTION,progress);
    SETOPT(CURLOPT_XFERINFODATA,d);
    SETOPT(CURLOPT_NOPROGRESS,0L);
#undef SETOPT
    return 0;
}

static CURLcode perform_latest(CURL *curl) {
    CURLM *multi=curl_multi_init();
    if (!multi) return CURLE_FAILED_INIT;
    CURLcode result=CURLE_FAILED_INIT;
    if (curl_multi_add_handle(multi,curl)==CURLM_OK) {
        int running=0;
        CURLMcode rc=curl_multi_perform(multi,&running);
        while (rc==CURLM_OK && running) {
            rc=curl_multi_poll(multi,NULL,0,40,NULL);
            if (rc==CURLM_OK) rc=curl_multi_perform(multi,&running);
        }
        int pending=0;
        CURLMsg *message=curl_multi_info_read(multi,&pending);
        if (rc==CURLM_OK && message && message->msg==CURLMSG_DONE)
            result=message->data.result;
        curl_multi_remove_handle(multi,curl);
    }
    curl_multi_cleanup(multi);
    return result;
}

static int latest_version(CURL *curl,SkaterUpdate *out) {
    if (configure(curl,RELEASES "latest",NULL,true)) return -1;
    CURLcode rc=perform_latest(curl); long status=0; char *target=NULL;
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    curl_easy_getinfo(curl,CURLINFO_REDIRECT_URL,&target);
#ifdef SKATER_UPDATE_TIMINGS
    double dns=0,tcp=0,tls=0,first=0,total=0;
    curl_easy_getinfo(curl,CURLINFO_NAMELOOKUP_TIME,&dns);
    curl_easy_getinfo(curl,CURLINFO_CONNECT_TIME,&tcp);
    curl_easy_getinfo(curl,CURLINFO_APPCONNECT_TIME,&tls);
    curl_easy_getinfo(curl,CURLINFO_STARTTRANSFER_TIME,&first);
    curl_easy_getinfo(curl,CURLINFO_TOTAL_TIME,&total);
    printf("Check ms: DNS %.0f TCP %.0f TLS %.0f\nServer %.0f Total %.0f\n",
           dns*1000,(tcp-dns)*1000,(tls-tcp)*1000,(first-tls)*1000,total*1000);
    mkdir("sdmc:/3ds",0777); mkdir(UPDATE_DIR,0777);
    FILE *timing=fopen(UPDATE_DIR "/update-check.log","w");
    if (timing) {
        fprintf(timing,"method=HEAD\nfollow_redirects=0\nhttp=%ld\ncurl=%d\ndns_ms=%.3f\ntcp_ms=%.3f\ntls_ms=%.3f\nserver_ms=%.3f\nrequest_ms=%.3f\nwhole_check_ms=%llu\n",
                status,(int)rc,dns*1000,(tcp-dns)*1000,(tls-tcp)*1000,(first-tls)*1000,total*1000,
                (unsigned long long)(osGetTime()-check_start));
        fclose(timing);
    }
#endif
    if (status==404) return 1;
    const char prefix[]=RELEASES "tag/";
    if (rc!=CURLE_OK || (status!=301 && status!=302 && status!=307 && status!=308) ||
        !target || strncmp(target,prefix,sizeof(prefix)-1)) {
        printf("Release check failed (%d / HTTP %ld).\n",(int)rc,status); return -1;
    }
    const char *tag=target+sizeof(prefix)-1;
    return skater_update_tag(tag,strlen(tag),out);
}

static int download(CURL *curl,const char *url,Download *d) {
    sha256_init(&d->hash);
    if (configure(curl,url,d,false)) return -1;
    long status=0; CURLcode rc=curl_easy_perform(curl);
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    if (rc!=CURLE_OK || status!=200) {
        printf("Update download failed (%d / HTTP %ld).\n",(int)rc,status); return -1;
    }
    return 0;
}

static int confirm(void) {
    printf("A  Update patcher\nB  Cancel\n");
    while (aptMainLoop()) {
        hidScanInput(); u32 down=hidKeysDown();
        if (down&KEY_B) return 0;
        if (down&KEY_A) return 1;
        gspWaitForVBlank();
    }
    return 0;
}

static int install_cia(size_t size,unsigned version) {
    Handle source=0,install=0; AM_TitleInfo info={0};
    Result rc=amInit(); if (R_FAILED(rc)) return -1;
    rc=FSUSER_OpenFileDirectly(&source,ARCHIVE_SDMC,fsMakePath(PATH_EMPTY,""),
                              fsMakePath(PATH_ASCII,"/3ds/skater-plus-patcher/update.tmp"),FS_OPEN_READ,0);
    if (R_SUCCEEDED(rc)) rc=AM_GetCiaFileInfo(MEDIATYPE_SD,&info,source);
    if (R_SUCCEEDED(rc) && (info.titleID!=OWN_TITLE || info.version!=version)) rc=-1;
    if (R_SUCCEEDED(rc)) rc=AM_StartCiaInstall(MEDIATYPE_SD,&install);
    u8 buffer[16384];
    for (u64 offset=0;R_SUCCEEDED(rc) && offset<size;) {
        u32 got=0,written=0,n=(u32)((size-offset)<sizeof(buffer)?size-offset:sizeof(buffer));
        rc=FSFILE_Read(source,&got,offset,buffer,n);
        if (R_SUCCEEDED(rc) && got!=n) rc=-1;
        if (R_SUCCEEDED(rc)) rc=FSFILE_Write(install,&written,offset,buffer,n,0);
        if (R_SUCCEEDED(rc) && written!=n) rc=-1;
        offset+=n;
    }
    if (install) {
        if (R_SUCCEEDED(rc)) rc=AM_FinishCiaInstall(install);
        if (R_FAILED(rc)) AM_CancelCIAInstall(install);
    }
    if (source) FSFILE_Close(source);
    amExit();
    if (R_FAILED(rc)) { printf("CIA update failed: %08lX\n",(unsigned long)rc); return -1; }
    return 0;
}

static int install_3dsx(const char *launch_path,size_t new_size) {
    if (!launch_path || strncmp(launch_path,"sdmc:/",6) || strlen(launch_path)>220 ||
        strlen(launch_path)<11 || strcmp(launch_path+strlen(launch_path)-5,".3dsx") ||
        strstr(launch_path,"/../") || strstr(launch_path,"/./")) {
        printf("Unsupported HBL path: %s\n",launch_path?launch_path:"(missing)"); return -1;
    }
    FILE *input=fopen(STAGED,"rb"); char magic[4];
    if (!input) { printf("Open staged file failed: %d\n",errno); return -1; }
    if (fread(magic,1,4,input)!=4 || memcmp(magic,"3DSX",4) || fseek(input,0,SEEK_SET)) {
        fclose(input); printf("Downloaded file is not 3DSX.\n"); return -1;
    }
    struct stat st;
    if (stat(launch_path,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>SKATER_UPDATE_MAX_FILE) {
        fclose(input); printf("Invalid HBL source: %s\n",launch_path); return -1;
    }
    size_t old_size=(size_t)st.st_size;
    u8 *old=malloc(old_size);
    if (!old) { fclose(input); printf("Not enough memory for update.\n"); return -1; }
    FILE *output=fopen(launch_path,"r+b");
    if (!output) { free(old); fclose(input); printf("Open HBL executable failed: %d\n",errno); return -1; }
    /* Keep rollback data in RAM only; do not rename the running executable. */
    if (fread(old,1,old_size,output)!=old_size || fseek(output,0,SEEK_SET)) {
        fclose(output); free(old); fclose(input); printf("Read HBL executable failed.\n"); return -1;
    }
    u8 chunk[16384]; int rc=0;
    for (size_t offset=0;offset<new_size;) {
        size_t n=new_size-offset; if (n>sizeof(chunk)) n=sizeof(chunk);
        if (fread(chunk,1,n,input)!=n || fwrite(chunk,1,n,output)!=n) { rc=-1; break; }
        offset+=n;
    }
    if (fflush(output) || ftruncate(fileno(output),(off_t)new_size) || fsync(fileno(output))) rc=-1;
    if (rc) {
        printf("Write HBL executable failed: %d\n",errno);
        clearerr(output);
        if (fseek(output,0,SEEK_SET) || fwrite(old,1,old_size,output)!=old_size ||
            fflush(output) || ftruncate(fileno(output),(off_t)old_size) || fsync(fileno(output)))
            printf("Could not restore the previous executable.\n");
    }
    if (fclose(output)) rc=-1;
    free(old); fclose(input); return rc;
}

int updater_check(const char *launch_path) {
#ifdef SKATER_UPDATE_TIMINGS
    check_start=osGetTime();
#endif
    int updated=0; Network net={0}; CURL *curl=NULL;
    last_check="Check unavailable";
    printf("\nChecking latest version... B cancels.\n");
    if (network_open(&net)) { printf("Network/TLS unavailable.\n"); return 0; }
    curl=curl_easy_init(); if (!curl) goto done;
    SkaterUpdate latest,release;
    int rc=latest_version(curl,&latest);
    if (rc==1) { last_check="No release published"; printf("No release published yet.\n"); goto done; }
    if (rc) goto done;
    if (latest.title_version<=SKATER_TITLE_VERSION) {
        last_check="Up to date"; printf("Patcher is up to date.\n"); goto done;
    }
    last_check="New version available";
    printf("Available: %s (current " SKATER_VERSION ")\n",latest.version);
    if (!confirm()) goto done;
    /* Hash metadata is needed only after accepting an actual update. */
    char metadata[SKATER_UPDATE_MAX_MANIFEST],manifest_url[256];
    snprintf(manifest_url,sizeof(manifest_url),RELEASES "download/v%s/update.txt",latest.version);
    Download manifest={.memory=metadata,.limit=sizeof(metadata)};
    if (download(curl,manifest_url,&manifest) || skater_update_parse(metadata,manifest.size,&release) ||
        release.title_version!=latest.title_version || strcmp(release.version,latest.version)) {
        printf("Update metadata validation failed.\n"); goto done;
    }
    mkdir("sdmc:/3ds",0777); mkdir(UPDATE_DIR,0777);
    unsigned kind=envIsHomebrew()?1:0;
    char url[256]; snprintf(url,sizeof(url),RELEASES "download/v%s/skater-plus-patcher.%s",release.version,kind?"3dsx":"cia");
    Download asset={.file=fopen(STAGED,"wb"),.limit=release.size[kind]};
    if (!asset.file) { printf("Create download file failed: %d\n",errno); goto done; }
    rc=download(curl,url,&asset);
    if (fflush(asset.file)) { printf("Download flush failed: %d\n",errno); rc=-1; }
    if (fsync(fileno(asset.file))) { printf("Download sync failed: %d\n",errno); rc=-1; }
    if (fclose(asset.file)) { printf("Download close failed: %d\n",errno); rc=-1; }
    u8 digest[32]; sha256_final(&asset.hash,digest);
    if (!rc && asset.size!=release.size[kind]) {
        printf("Download size mismatch: %lu / %lu\n",(unsigned long)asset.size,(unsigned long)release.size[kind]); rc=-1;
    }
    if (!rc && memcmp(digest,release.sha256[kind],32)) { printf("Download SHA-256 mismatch.\n"); rc=-1; }
    if (!rc) rc=kind ? install_3dsx(launch_path,asset.size) : install_cia(asset.size,release.title_version);
    remove(STAGED);
    if (rc) printf("Update not installed.\n");
    else {
        updated=1;
        printf("Patcher updated. Exit and reopen it.\nThen update the browser patch there.\n");
    }
done:
    if (curl) curl_easy_cleanup(curl);
    network_close(&net); return updated;
}
