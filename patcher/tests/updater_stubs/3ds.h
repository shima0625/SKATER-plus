#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
typedef int Result; typedef unsigned Handle;
typedef struct TestThread *Thread;
Thread threadCreate(void (*)(void *),void *,size_t,int,int,bool);
Result threadJoin(Thread,uint64_t); void threadFree(Thread);
typedef struct { u64 titleID; uint16_t version; } AM_TitleInfo;
#define R_FAILED(r) ((r)<0)
#define R_SUCCEEDED(r) ((r)>=0)
#define KEY_A 1u
#define KEY_B 2u
#define MEDIATYPE_SD 1
#define ARCHIVE_SDMC 1
#define PATH_EMPTY 0
#define PATH_ASCII 1
#define FS_OPEN_READ 1
void hidScanInput(void); u32 hidKeysDown(void); bool aptMainLoop(void);
void gspWaitForVBlank(void); bool envIsHomebrew(void);
Result socInit(void *,unsigned); void socExit(void);
Result sslcInit(Handle); void sslcExit(void); Result sslcGenerateRandomData(u8 *,u32);
Result amInit(void); void amExit(void);
const char *fsMakePath(unsigned,const char *);
Result FSUSER_OpenFileDirectly(Handle *,unsigned,const char *,const char *,unsigned,unsigned);
Result AM_GetCiaFileInfo(unsigned,AM_TitleInfo *,Handle);
Result AM_StartCiaInstall(unsigned,Handle *);
Result AM_FinishCiaInstall(Handle); Result AM_CancelCIAInstall(Handle);
Result FSFILE_Read(Handle,u32 *,u64,void *,u32);
Result FSFILE_Write(Handle,u32 *,u64,const void *,u32,unsigned);
void FSFILE_Close(Handle);
