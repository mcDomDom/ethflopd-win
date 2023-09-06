#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <ntddndis.h>

#ifndef NDIS_IF_MAX_STRING_SIZE
#define NDIS_IF_MAX_STRING_SIZE IF_MAX_STRING_SIZE   /* =256 in <ifdef.h> */
#endif

#ifndef NETIO_STATUS
#define NETIO_STATUS DWORD
#endif
#if 0
/**********************************************************************************/
/* Get the friendly name for the given GUID */
char *
get_interface_friendly_name_from_device_guid(__in GUID *guid)
{
    HMODULE hIPHlpApi;
    HRESULT status;
    WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
    HRESULT hr;
    BOOL fallbackToUnpublishedApi=TRUE;
    BOOL haveInterfaceFriendlyName=FALSE;
    int size;
    char *name;

    /* Load the ip helper api DLL */
    hIPHlpApi = LoadLibrary(TEXT("iphlpapi.dll"));
    if (hIPHlpApi == NULL) {
        /* Load failed - DLL should always be available in XP+*/
        return NULL;
    }

    /* Need to convert an Interface GUID to the interface friendly name (e.g. "Local Area Connection")
    * The functions required to do this all reside within iphlpapi.dll
    * - The preferred approach is to use published API functions (Available since Windows Vista)
    * - We do however fallback to trying undocumented API if the published API is not available (Windows XP/2k3 scenario)
    */

    if(IsWindowsVistaOrLater()){
        /* Published API function prototypes (for Windows Vista/Windows Server 2008+) */
        typedef NETIO_STATUS (WINAPI *ProcAddr_CIG2L) (__in CONST GUID *InterfaceGuid, __out PNET_LUID InterfaceLuid);
        typedef NETIO_STATUS (WINAPI *ProcAddr_CIL2A) ( __in CONST NET_LUID *InterfaceLuid,__out_ecount(Length) PWSTR InterfaceAlias, __in SIZE_T Length);

        /* Attempt to do the conversion using Published API functions */
        ProcAddr_CIG2L proc_ConvertInterfaceGuidToLuid=(ProcAddr_CIG2L) GetProcAddress(hIPHlpApi, "ConvertInterfaceGuidToLuid");
        if(proc_ConvertInterfaceGuidToLuid!=NULL){
            ProcAddr_CIL2A Proc_ConvertInterfaceLuidToAlias=(ProcAddr_CIL2A) GetProcAddress(hIPHlpApi, "ConvertInterfaceLuidToAlias");
            if(Proc_ConvertInterfaceLuidToAlias!=NULL){
                /* we have our functions ready to go, attempt to convert interface guid->luid->friendlyname */
                NET_LUID InterfaceLuid;
                hr = proc_ConvertInterfaceGuidToLuid(guid, &InterfaceLuid);
                if(hr==NO_ERROR){
                    /* guid->luid success */
                    hr = Proc_ConvertInterfaceLuidToAlias(&InterfaceLuid, wName, NDIS_IF_MAX_STRING_SIZE+1);

                    if(hr==NO_ERROR){
                        /* luid->friendly name success */
                        haveInterfaceFriendlyName=TRUE; /* success */
                    }else{
                        /* luid->friendly name failed */
                        fallbackToUnpublishedApi=FALSE;
                    }
                }else{
                    fallbackToUnpublishedApi=FALSE;
                }

            }
        }
    }


    if(fallbackToUnpublishedApi && !haveInterfaceFriendlyName){
        /* Didn't manage to get the friendly name using published api functions
        * (most likely cause wireshark is running on Windows XP/Server 2003)
        * Retry using nhGetInterfaceNameFromGuid (an older unpublished API function) */
        typedef HRESULT (WINAPI *ProcAddr_nhGINFG) (__in GUID *InterfaceGuid, __out PCWSTR InterfaceAlias, __inout DWORD *LengthAddress, wchar_t *a4, wchar_t *a5);

        ProcAddr_nhGINFG Proc_nhGetInterfaceNameFromGuid = NULL;
        Proc_nhGetInterfaceNameFromGuid = (ProcAddr_nhGINFG) GetProcAddress(hIPHlpApi, "NhGetInterfaceNameFromGuid");
        if (Proc_nhGetInterfaceNameFromGuid!= NULL) {
            wchar_t *p4=NULL, *p5=NULL;
            DWORD NameSize;

            /* testing of nhGetInterfaceNameFromGuid indicates the unpublished API function expects the 3rd parameter
            * to be the available space in bytes (as compared to wchar's) available in the second parameter buffer
            * to receive the friendly name (in unicode format) including the space for the nul termination.*/
            NameSize = sizeof(wName);

            /* do the guid->friendlyname lookup */
            status = Proc_nhGetInterfaceNameFromGuid(guid, wName, &NameSize, p4, p5);

            if(status==0){
                haveInterfaceFriendlyName=TRUE; /* success */
            }
        }
    }

    /* we have finished with iphlpapi.dll - release it */
    FreeLibrary(hIPHlpApi);

    if(!haveInterfaceFriendlyName){
        /* failed to get the friendly name, nothing further to do */
        return NULL;
    }

    /* Get the required buffer size, and then convert the string
    * from UTF-16 to UTF-8. */
    size=WideCharToMultiByte(CP_ACP, 0, wName, -1, NULL, 0, NULL, NULL);
    name=(char *) malloc(size);
    if (name == NULL){
        return NULL;
    }
    size=WideCharToMultiByte(CP_ACP, 0, wName, -1, name, size, NULL, NULL);
    if(size==0){
        /* bytes written == 0, indicating some form of error*/
        free(name);
        return NULL;
    }
    return name;
}
#endif

/*
 * Given an interface name, try to extract the GUID from it and parse it.
 * If that fails, return NULL; if that succeeds, attempt to get the
 * friendly name for the interface in question.  If that fails, return
 * NULL, otherwise return the friendly name, allocated with g_malloc()
 * (so that it must be freed with g_free()).
 */
char *GetNetworkInterfaceName(const char *szDeviceName)
{
	DWORD dwRet;
    const char* szGuid;
    GUID guid;
	NET_LUID luid;
	char szStripedGuid[256];
	WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
	static char szName[NDIS_IF_MAX_STRING_SIZE + 1];
    int size;
    
    szGuid = (strncmp("\\Device\\NPF_", szDeviceName, 12)==0) ?  szDeviceName+12 : szDeviceName;

	strcpy(szStripedGuid, &szGuid[1]);
	szStripedGuid[36] = '\0';
	if (UuidFromString((RPC_CSTR)szStripedGuid, &guid) != RPC_S_OK) {
		return NULL;
	}

	dwRet = ConvertInterfaceGuidToLuid(&guid, &luid);
	if (dwRet != NO_ERROR) {
		return NULL;
	}

	dwRet = ConvertInterfaceLuidToAlias(&luid, wName, NDIS_IF_MAX_STRING_SIZE+1);
	if (dwRet != NO_ERROR) {
		return NULL;
	}

	size=WideCharToMultiByte(CP_ACP, 0, wName, -1, szName, NDIS_IF_MAX_STRING_SIZE+1, NULL, NULL);
    if(size==0){
        return NULL;
    }

    /* guid okay, get the interface friendly name associated with the guid */
    return szName;
}
