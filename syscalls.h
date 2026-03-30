#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <windows.h>

#ifndef __cplusplus
extern "C" {
#endif

typedef long NTSTATUS;
extern "C" NTSTATUS NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                  POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
#ifdef __cpluscplus
}
#endif
#endif
