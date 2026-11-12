/* Actual updater orchestration with injected network/AM boundaries; no device access. */
#include <3ds.h>
#include <curl/curl.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "sha256.h"
#include "updater.h"

struct TestCurl {
    char url[256]; void *user;
    size_t (*write)(char *,size_t,size_t,void *);
    int peer,host,https,redirect_https,head,follow;
    long status; char redirect[256];
};
static char metadata[512];
static const char executable[]="3DSXtest executable";
static bool homebrew=true,cancel=false,bad_title=false,bad_version=false,fail_write=false,fail_finish=false;
static bool fail_options=false,fail_network=false;
static int requests,started,finished,aborted,global_cleanup,socket_cleanup;
static long response_status=200;
static size_t installed_size;
static FILE *source;
static const char *override_redirect;

CURL *curl_easy_init(void) { return calloc(1,sizeof(CURL)); }
void curl_easy_cleanup(CURL *c) { free(c); }
void curl_easy_reset(CURL *c) { memset(c,0,sizeof(*c)); }
CURLcode curl_global_init(long unused) { (void)unused; return 0; }
void curl_global_cleanup(void) { global_cleanup++; }
CURLcode curl_easy_setopt(CURL *c,int key,...) {
    va_list a; va_start(a,key); int rc=0;
    if (fail_options) rc=2;
    else switch (key) {
    case CURLOPT_URL: snprintf(c->url,sizeof(c->url),"%s",va_arg(a,const char *)); break;
    case CURLOPT_USERAGENT: case CURLOPT_CAINFO: (void)va_arg(a,const char *); break;
    case CURLOPT_CAINFO_BLOB: { struct curl_blob *b=va_arg(a,struct curl_blob *); assert(b->data && b->len); break; }
    case CURLOPT_PROTOCOLS_STR: c->https=!strcmp(va_arg(a,const char *),"https"); break;
    case CURLOPT_REDIR_PROTOCOLS_STR: c->redirect_https=!strcmp(va_arg(a,const char *),"https"); break;
    case CURLOPT_WRITEFUNCTION: c->write=va_arg(a,size_t (*)(char *,size_t,size_t,void *)); break;
    case CURLOPT_NOBODY: c->head=va_arg(a,long)!=0; break;
    case CURLOPT_FOLLOWLOCATION: c->follow=va_arg(a,long)!=0; break;
    case CURLOPT_WRITEDATA: c->user=va_arg(a,void *); break;
    case CURLOPT_XFERINFODATA: (void)va_arg(a,void *); break;
    case CURLOPT_XFERINFOFUNCTION: (void)va_arg(a,int (*)(void *,curl_off_t,curl_off_t,curl_off_t,curl_off_t)); break;
    case CURLOPT_SSL_VERIFYPEER: c->peer=va_arg(a,long)==1; break;
    case CURLOPT_SSL_VERIFYHOST: c->host=va_arg(a,long)==2; break;
    default: (void)va_arg(a,long); break;
    }
    va_end(a); return rc;
}
CURLcode curl_easy_perform(CURL *c) {
    requests++; assert(c->peer && c->host && c->https && c->redirect_https);
    if (fail_network) return 7;
    if (response_status!=200) { c->status=response_status; return 22; }
    if (c->head) {
        assert(!c->follow && !strcmp(c->url,"https://github.com/shima0625/SKATER-plus/releases/latest"));
        const char *version=strchr(metadata,'\n');
        char tag[32]="0.1.2";
        if (version && strchr(++version,'\n')) {
            size_t n=(size_t)(strchr(version,'\n')-version); assert(n<sizeof(tag)); memcpy(tag,version,n); tag[n]=0;
        }
        snprintf(c->redirect,sizeof(c->redirect),"https://github.com/shima0625/SKATER-plus/releases/tag/v%s",tag);
        if (override_redirect) snprintf(c->redirect,sizeof(c->redirect),"%s",override_redirect);
        c->status=302; return 0;
    }
    assert(c->follow); c->status=200;
    const char *data=strstr(c->url,"update.txt")?metadata:executable;
    if (!strstr(c->url,"update.txt")) assert(strstr(c->url,"/download/v0.1.2/skater-plus-patcher."));
    size_t n=strlen(data); return c->write((char *)data,1,n,c->user)==n?0:23;
}
struct TestMulti { CURL *easy; CURLMsg message; bool polled; };
CURLM *curl_multi_init(void) { return calloc(1,sizeof(CURLM)); }
CURLMcode curl_multi_add_handle(CURLM *m,CURL *c) { m->easy=c; return CURLM_OK; }
CURLMcode curl_multi_remove_handle(CURLM *m,CURL *c) { assert(m->easy==c); m->easy=NULL; return CURLM_OK; }
CURLMcode curl_multi_poll(CURLM *m,void *fds,unsigned count,int timeout,int *ready) {
    assert(!fds && !count && timeout==40 && !ready);
    m->polled=true;
    return CURLM_OK;
}
CURLMcode curl_multi_perform(CURLM *m,int *running) {
    *running=!m->polled;
    if (!*running) {
        m->message.msg=CURLMSG_DONE;
        m->message.data.result=curl_easy_perform(m->easy);
    }
    return CURLM_OK;
}
CURLMsg *curl_multi_info_read(CURLM *m,int *pending) { *pending=0; return &m->message; }
CURLMcode curl_multi_cleanup(CURLM *m) { assert(!m->easy); free(m); return CURLM_OK; }
CURLcode curl_easy_getinfo(CURL *c,int key,...) {
    va_list a; va_start(a,key);
    if (key==CURLINFO_RESPONSE_CODE) *va_arg(a,long *)=c->status;
    else if (key==CURLINFO_REDIRECT_URL) *va_arg(a,char **)=c->head?c->redirect:NULL;
    else *va_arg(a,double *)=0.1;
    va_end(a); return 0;
}

void hidScanInput(void) {} u32 hidKeysDown(void) { return cancel?KEY_B:KEY_A; }
bool aptMainLoop(void) { return true; } void gspWaitForVBlank(void) { usleep(1000); }
bool envIsHomebrew(void) { return homebrew; }
Result socInit(void *p,unsigned n) { (void)p; (void)n; return 0; }
void socExit(void) { socket_cleanup++; }
Result sslcInit(Handle h) { (void)h; return 0; } void sslcExit(void) {}
Result sslcGenerateRandomData(u8 *out,u32 n) { memset(out,1,n); return 0; }
Result amInit(void) { return 0; } void amExit(void) {}
const char *fsMakePath(unsigned kind,const char *path) { (void)kind; return path; }
Result FSUSER_OpenFileDirectly(Handle *out,unsigned a,const char *b,const char *c,unsigned d,unsigned e) {
    (void)a;(void)b;(void)c;(void)d;(void)e;
    source=fopen("sdmc:/3ds/skater-plus-patcher/update.tmp","rb"); *out=source?1:0; return source?0:-1;
}
Result AM_GetCiaFileInfo(unsigned type,AM_TitleInfo *out,Handle h) {
    (void)type;(void)h; out->titleID=bad_title?1:UINT64_C(0x000400000F5A5400); out->version=bad_version?19:18; return 0;
}
Result AM_StartCiaInstall(unsigned type,Handle *out) { (void)type; *out=2; started++; return 0; }
Result AM_FinishCiaInstall(Handle h) { (void)h; if (fail_finish) return -1; finished++; return 0; }
Result AM_CancelCIAInstall(Handle h) { (void)h; aborted++; return 0; }
Result FSFILE_Read(Handle h,u32 *n,u64 off,void *buf,u32 count) {
    (void)h; assert(!fseek(source,(long)off,SEEK_SET)); *n=(u32)fread(buf,1,count,source); return 0;
}
Result FSFILE_Write(Handle h,u32 *n,u64 off,const void *buf,u32 count,unsigned flags) {
    (void)h;(void)off;(void)buf;(void)flags;
    if (fail_write) return -1;
    *n=count; installed_size+=count; return 0;
}
void FSFILE_Close(Handle h) { (void)h; fclose(source); source=NULL; }

static void manifest(size_t size) {
    u8 digest[32]; sha256_buffer(executable,strlen(executable),digest);
    char hash[65]; for (unsigned i=0;i<32;i++) snprintf(hash+i*2,3,"%02x",digest[i]);
    snprintf(metadata,sizeof(metadata),"SKATER-UPDATE-1\n0.1.2\ncia %zu %s\n3dsx %zu %s\n",size,hash,size,hash);
}
static void put(const char *path,const char *text) {
    FILE *f=fopen(path,"wb"); assert(f); assert(fwrite(text,1,strlen(text),f)==strlen(text)); assert(!fclose(f));
}
static void equal_file(const char *path,const char *text) {
    char buf[64]={0}; FILE *f=fopen(path,"rb"); assert(f); size_t n=fread(buf,1,sizeof(buf),f); fclose(f);
    assert(n==strlen(text) && !memcmp(buf,text,n));
}
int main(void) {
    char temporary[]="/tmp/skater-updater-test.XXXXXX";
    assert(mkdtemp(temporary)); assert(!chdir(temporary));
    mkdir("sdmc:",0700); mkdir("sdmc:/3ds",0700); mkdir("sdmc:/3ds/skater-plus-patcher",0700);
    const char *path="sdmc:/3ds/test.3dsx", *backup="sdmc:/3ds/test.3dsx.previous";
    put(path,"old"); manifest(strlen(executable));
    assert(updater_check(path)==1); equal_file(path,executable); assert(access(backup,F_OK));
    put(path,"old");
    manifest(strlen(executable)+1); assert(!updater_check(path)); equal_file(path,"old");
    manifest(strlen(executable)-1); assert(!updater_check(path)); equal_file(path,"old");
    manifest(strlen(executable)); char *hash=strstr(metadata,"cia "); assert(hash); hash=strchr(hash+4,' ')+1; hash[0]=hash[0]=='0'?'1':'0';
    homebrew=false; assert(!updater_check(path)); assert(!started);
    manifest(strlen(executable)); cancel=true; int before=requests;
    assert(!updater_check(path)); assert(requests==before+1); cancel=false;
    homebrew=true; assert(!updater_check("other:/test.3dsx")); equal_file(path,"old");
    put(backup,"backup"); assert(updater_check(path)==1); equal_file(backup,"backup"); equal_file(path,executable); remove(backup); put(path,"old");
    homebrew=false; bad_title=true; assert(!updater_check(path)); assert(!started); bad_title=false;
    bad_version=true; assert(!updater_check(path)); assert(!started); bad_version=false;
    fail_write=true; assert(!updater_check(path)); assert(started==1 && aborted==1 && !finished); fail_write=false;
    assert(updater_check(path)==1); assert(started==2 && finished==1 && installed_size==strlen(executable));
    fail_finish=true; assert(!updater_check(path)); assert(started==3 && aborted==2 && finished==1); fail_finish=false;
    fail_options=true; before=requests; assert(!updater_check(path)); assert(requests==before); fail_options=false;
    fail_network=true; assert(!updater_check(path)); fail_network=false;
    strcpy(metadata,"broken"); before=requests; assert(!updater_check(path)); assert(requests==before+2);
    response_status=404; before=requests; assert(!updater_check(path)); assert(requests==before+1); response_status=200;
    manifest(strlen(executable)); strstr(metadata,"0.1.2")[4]='1'; before=requests;
    assert(!updater_check(path)); assert(requests==before+1);
    manifest(strlen(executable)); strstr(metadata,"0.1.2")[4]='0'; before=requests;
    assert(!updater_check(path)); assert(requests==before+1);
    assert(global_cleanup==18 && socket_cleanup==18);
    manifest(strlen(executable));
    override_redirect="https://other.test/releases/tag/v9.9.9"; before=requests;
    assert(!updater_check(path)); assert(requests==before+1);
    override_redirect="https://github.com/shima0625/SKATER-plus/releases/tag/v0.1.2-beta"; before=requests;
    assert(!updater_check(path)); assert(requests==before+1); override_redirect=NULL;
    assert(global_cleanup==20 && socket_cleanup==20);
    puts("PASS updater: 20 scenarios including one-request current-version checks, no redirect following and wrong-tag rejection (network/AM mocks)"); return 0;
}
