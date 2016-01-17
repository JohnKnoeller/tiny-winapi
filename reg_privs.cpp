#include "tiny_winapi.h"

// need the advapi library for working with security
#pragma comment(linker, "/defaultlib:advapi32.lib")

// the access mask is a DWORD where low bits are type specific rights and upper bits are generic rights
//
//      +---------------+---------------+-------------------------------+
//      |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
//      |R|W|E|A|     |S|               |                               |
//      +-+-------------+---------------+-------------------------------+
//      AS is AccessSystemAcl
//      GA is GenericAll
//      GE is GenericExecute
//      GW is GenericWrite
//      GR is GenericRead

//
#define DELETE_RIGHT                     0x00010000
#define READ_CONTROL_RIGHT               0x00020000
#define WRITE_DAC_RIGHT                  0x00040000
#define WRITE_OWNER_RIGHT                0x00080000
#define SYNCHRONIZE_RIGHT                0x00100000

#define STANDARD_RIGHTS_READ             (READ_CONTROL_RIGHT)
#define STANDARD_RIGHTS_WRITE            (READ_CONTROL_RIGHT)
#define STANDARD_RIGHTS_EXECUTE          (READ_CONTROL_RIGHT)
#define STANDARD_RIGHTS_ALL              0x001F0000


#define ACCESS_SYSTEM_SECURITY           0x01000000

#define GENERIC_READ                     0x80000000
#define GENERIC_WRITE                    0x40000000
#define GENERIC_EXECUTE                  0x20000000
#define GENERIC_ALL                      0x10000000

// Token special rights.
#define TOKEN_ASSIGN_PRIMARY    0x0001
#define TOKEN_DUPLICATE         0x0002
#define TOKEN_IMPERSONATE       0x0004
#define TOKEN_QUERY             0x0008
#define TOKEN_QUERY_SOURCE      0x0010
#define TOKEN_ADJUST_PRIVILEGES 0x0020
#define TOKEN_ADJUST_GROUPS     0x0040
#define TOKEN_ADJUST_DEFAULT    0x0080
#define TOKEN_ADJUST_SESSIONID  0x0100
#define TOKEN_READ              (STANDARD_RIGHTS_READ | TOKEN_QUERY)
#define TOKEN_WRITE             (STANDARD_RIGHTS_WRITE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT)
#define TOKEN_EXECUTE           (STANDARD_RIGHTS_EXECUTE)
extern "C" BOOL __stdcall OpenProcessToken(HANDLE hProc, UINT access, HANDLE * hToken);
extern "C" BOOL __stdcall OpenThreadToken(HANDLE hProc, UINT access, BOOL AsSelf, HANDLE * hToken);
#define ERROR_NO_TOKEN          1008


#pragma pack(push,4)
typedef _sqword LUID;
typedef struct _LUID_AND_ATTRIBUTES {
    LUID Luid;
    UINT Attributes;
} LUID_AND_ATTRIBUTES;
typedef struct _TOKEN_PRIVILEGES {
    UINT PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES;
#pragma pack(pop)
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001
#define SE_PRIVILEGE_ENABLED            0x00000002
#define SE_PRIVILEGE_REMOVED            0x00000004
#define SE_PRIVILEGE_USED_FOR_ACCESS    0x80000000

#define SE_CREATE_TOKEN_NAME              L"SeCreateTokenPrivilege"
#define SE_ASSIGNPRIMARYTOKEN_NAME        L"SeAssignPrimaryTokenPrivilege"
#define SE_LOCK_MEMORY_NAME               L"SeLockMemoryPrivilege"
#define SE_INCREASE_QUOTA_NAME            L"SeIncreaseQuotaPrivilege"
#define SE_UNSOLICITED_INPUT_NAME         L"SeUnsolicitedInputPrivilege"
#define SE_MACHINE_ACCOUNT_NAME           L"SeMachineAccountPrivilege"
#define SE_TCB_NAME                       L"SeTcbPrivilege"
#define SE_SECURITY_NAME                  L"SeSecurityPrivilege"
#define SE_TAKE_OWNERSHIP_NAME            L"SeTakeOwnershipPrivilege"
#define SE_LOAD_DRIVER_NAME               L"SeLoadDriverPrivilege"
#define SE_SYSTEM_PROFILE_NAME            L"SeSystemProfilePrivilege"
#define SE_SYSTEMTIME_NAME                L"SeSystemtimePrivilege"
#define SE_PROF_SINGLE_PROCESS_NAME       L"SeProfileSingleProcessPrivilege"
#define SE_INC_BASE_PRIORITY_NAME         L"SeIncreaseBasePriorityPrivilege"
#define SE_CREATE_PAGEFILE_NAME           L"SeCreatePagefilePrivilege"
#define SE_CREATE_PERMANENT_NAME          L"SeCreatePermanentPrivilege"
#define SE_BACKUP_NAME                    L"SeBackupPrivilege"
#define SE_RESTORE_NAME                   L"SeRestorePrivilege"
#define SE_SHUTDOWN_NAME                  L"SeShutdownPrivilege"
#define SE_DEBUG_NAME                     L"SeDebugPrivilege"
#define SE_AUDIT_NAME                     L"SeAuditPrivilege"
#define SE_SYSTEM_ENVIRONMENT_NAME        L"SeSystemEnvironmentPrivilege"
#define SE_CHANGE_NOTIFY_NAME             L"SeChangeNotifyPrivilege"
#define SE_REMOTE_SHUTDOWN_NAME           L"SeRemoteShutdownPrivilege"
#define SE_UNDOCK_NAME                    L"SeUndockPrivilege"
#define SE_SYNC_AGENT_NAME                L"SeSyncAgentPrivilege"
#define SE_ENABLE_DELEGATION_NAME         L"SeEnableDelegationPrivilege"
#define SE_MANAGE_VOLUME_NAME             L"SeManageVolumePrivilege"
#define SE_IMPERSONATE_NAME               L"SeImpersonatePrivilege"
#define SE_CREATE_GLOBAL_NAME             L"SeCreateGlobalPrivilege"
#define SE_TRUSTED_CREDMAN_ACCESS_NAME    L"SeTrustedCredManAccessPrivilege"
#define SE_RELABEL_NAME                   L"SeRelabelPrivilege"
#define SE_INC_WORKING_SET_NAME           L"SeIncreaseWorkingSetPrivilege"
#define SE_TIME_ZONE_NAME                 L"SeTimeZonePrivilege"
#define SE_CREATE_SYMBOLIC_LINK_NAME      L"SeCreateSymbolicLinkPrivilege"

extern "C" BOOL __stdcall LookupPrivilegeValueW(const wchar_t * system_name, const wchar_t * se_name, LUID * pLuid);
extern "C" BOOL __stdcall LookupPrivilegeNameW(const wchar_t * system_name,  const LUID * pLuid, wchar_t * buf, UINT * pcchBuf); // pcchBuff is in and out param
extern "C" BOOL __stdcall AdjustTokenPrivileges(HANDLE hToken, BOOL DisableAll, TOKEN_PRIVILEGES * NewPriv, UINT cbOld, TOKEN_PRIVILEGES * OldPriv, UINT * pcbRet);

typedef enum {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids,
    TokenSessionId,
    TokenGroupsAndPrivileges,
    TokenSessionReference,
    TokenSandBoxInert,
    TokenAuditPolicy,
    TokenOrigin,
    TokenElevationType,
    TokenLinkedToken,
    TokenElevation,
    TokenHasRestrictions,
    TokenAccessInformation,
    TokenVirtualizationAllowed,
    TokenVirtualizationEnabled,
    TokenIntegrityLevel,
    TokenUIAccess,
    TokenMandatoryPolicy,
    TokenLogonSid,
    TokenIsAppContainer,
    TokenCapabilities,
    TokenAppContainerSid,
    TokenAppContainerNumber,
    TokenUserClaimAttributes,
    TokenDeviceClaimAttributes,
    TokenRestrictedUserClaimAttributes,
    TokenRestrictedDeviceClaimAttributes,
    TokenDeviceGroups,
    TokenRestrictedDeviceGroups,
    TokenSecurityAttributes,
    TokenIsRestricted,
    MaxTokenInfoClass  // MaxTokenInfoClass should always be the last enum
};
extern "C" BOOL __stdcall GetTokenInformation(HANDLE hToken, int eInfo, void* pInfo, UINT cbInfo, UINT* pcbInfo);
#define ERROR_INSUFFICIENT_BUFFER  122

#define OWNER_SECURITY_INFORMATION       (0x00000001L)
#define GROUP_SECURITY_INFORMATION       (0x00000002L)
#define DACL_SECURITY_INFORMATION        (0x00000004L)
#define SACL_SECURITY_INFORMATION        (0x00000008L)
#define LABEL_SECURITY_INFORMATION       (0x00000010L)
#define ATTRIBUTE_SECURITY_INFORMATION   (0x00000020L)
#define SCOPE_SECURITY_INFORMATION       (0x00000040L)
#define BACKUP_SECURITY_INFORMATION      (0x00010000L)

#define PROTECTED_DACL_SECURITY_INFORMATION     (0x80000000L)
#define PROTECTED_SACL_SECURITY_INFORMATION     (0x40000000L)
#define UNPROTECTED_DACL_SECURITY_INFORMATION   (0x20000000L)
#define UNPROTECTED_SACL_SECURITY_INFORMATION   (0x10000000L)

// bit values for the Control field of the SECURITY_DESCRIPTOR
#define SE_OWNER_DEFAULTED               0x0001
#define SE_GROUP_DEFAULTED               0x0002
#define SE_DACL_PRESENT                  0x0004
#define SE_DACL_DEFAULTED                0x0008
#define SE_SACL_PRESENT                  0x0010
#define SE_SACL_DEFAULTED                0x0020
#define SE_DACL_AUTO_INHERIT_REQ         0x0100
#define SE_SACL_AUTO_INHERIT_REQ         0x0200
#define SE_DACL_AUTO_INHERITED           0x0400
#define SE_SACL_AUTO_INHERITED           0x0800
#define SE_DACL_PROTECTED                0x1000
#define SE_SACL_PROTECTED                0x2000
#define SE_RM_CONTROL_VALID              0x4000
#define SE_SELF_RELATIVE                 0x8000

typedef void* PSID;
typedef unsigned short WORD;
// ACL is an ACL header followed by 1 or more ACEs
// ACE is an ACE header followed by ace data
typedef struct _ACL {
    BYTE  AclRevision; // currently must be 2,3, or 4
    BYTE  Sbz1;
    WORD AclSize; // AclSize is the size, in bytes, allocated for the ACL.  This includes the ACL header, ACES, and remaining free space in the buffer.
    WORD AceCount;
    WORD Sbz2;
} ACL;
typedef struct _ACE_HEADER {
    BYTE  AceType;   // one of ace type enum, 0 = ACCESS_ALLOWED, 1=ACCESS_DENIED, values up to 0x13 are defined.
    BYTE  AceFlags;  // ace flags are defined below
    WORD  AceSize;   // size, in bytes, of ace.
} ACE_HEADER;

// AceFlags
#define OBJECT_INHERIT_ACE                (0x1)
#define CONTAINER_INHERIT_ACE             (0x2)
#define NO_PROPAGATE_INHERIT_ACE          (0x4)
#define INHERIT_ONLY_ACE                  (0x8)
#define INHERITED_ACE                     (0x10)
#define VALID_INHERIT_FLAGS               (0x1F)

// the most common ACEs follow this pattern
typedef struct _ACCESS_ACE {
    ACE_HEADER Header;
    UINT       Mask;     // one or more of access mask bits (i.e READ_CONTROL_RIGHT)
    UINT       SidStart; // sid to grant or deny grant is AceType==0, deny is AceType==1
} ACCESS_ACE;


typedef struct _SECURITY_DESCRIPTOR {
	BYTE  Revision;
	BYTE  Sbz1;
	WORD  Control;
	PSID  Owner;
	PSID  Group;
	ACL * Sacl;
	ACL * Dacl;
} SECURITY_DESCRIPTOR;

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
	BYTE  Revision;
	BYTE  Sbz1;
	WORD  Control;
	UINT  Owner;
	UINT  Group;
	UINT  Sacl;
	UINT  Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;

// Pictorially the structure of an SID is as follows:
//
//         1   1   1   1   1   1
//         5   4   3   2   1   0   9   8   7   6   5   4   3   2   1   0
//      +---------------------------------------------------------------+
//      |      SubAuthorityCount        |Reserved1 (SBZ)|   Revision    |
//      +---------------------------------------------------------------+
//      |                   IdentifierAuthority[0]                      |
//      +---------------------------------------------------------------+
//      |                   IdentifierAuthority[1]                      |
//      +---------------------------------------------------------------+
//      |                   IdentifierAuthority[2]                      |
//      +---------------------------------------------------------------+
//      |                                                               |
//      +- -  -  -  -  -  -  -  SubAuthority[]  -  -  -  -  -  -  -  - -+
//      |                                                               |
//      +---------------------------------------------------------------+

typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE  Value[6];
} SID_IDENTIFIER_AUTHORITY;

// SID_NAME_USE
typedef enum {
    SidTypeUser = 1,
    SidTypeGroup,
    SidTypeDomain,
    SidTypeAlias,
    SidTypeWellKnownGroup,
    SidTypeDeletedAccount,
    SidTypeInvalid,
    SidTypeUnknown,
    SidTypeComputer,
    SidTypeLabel
};


extern "C" SID_IDENTIFIER_AUTHORITY* __stdcall GetSidIdentifierAuthority(PSID pSid);
extern "C" BYTE* __stdcall GetSidSubAuthorityCount(PSID pSid);
extern "C" UINT* __stdcall GetSidSubAuthority(PSID pSid, UINT nSubAuthority);
extern "C" BYTE __stdcall LookupAccountSidW(const wchar_t * system_name, PSID psid, wchar_t * name, UINT * pcchName, wchar_t * domain, UINT* pcchDomain, int* peSidType);
#define ERROR_NONE_MAPPED 1332

typedef struct _HKEY { int dummy; } * HKEY;

#define KEY_QUERY_VALUE         0x0001
#define KEY_SET_VALUE           0x0002
#define KEY_CREATE_SUB_KEY      0x0004
#define KEY_ENUMERATE_SUB_KEYS  0x0008
#define KEY_NOTIFY              0x0010
#define KEY_CREATE_LINK         0x0020
#define KEY_WOW64_32KEY         0x0200
#define KEY_WOW64_64KEY         0x0100
#define KEY_WOW64_RES           0x0300

#define KEY_READ                (STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY)
#define KEY_WRITE               ((STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY)
#define KEY_EXECUTE             KEY_READ
#define KEY_ALL_ACCESS          (STANDARD_RIGHTS_ALL | KEY_READ | KEY_WRITE | KEY_NOTIFY | KEY_CREATE_LINK)

#define REG_OPTION_OPEN_LINK 0x00000008 // Open symbolic link (pass as ulOpts value to RegOpenKeyEx

#define HKEY_CLASSES_ROOT                   ((HKEY)(ULONG_PTR)0x80000000)
#define HKEY_CURRENT_USER                   ((HKEY)(ULONG_PTR)0x80000001)
#define HKEY_LOCAL_MACHINE                  ((HKEY)(ULONG_PTR)0x80000002)
#define HKEY_USERS                          ((HKEY)(ULONG_PTR)0x80000003)
#define HKEY_PERFORMANCE_DATA               ((HKEY)(ULONG_PTR)0x80000004)
#define HKEY_PERFORMANCE_TEXT               ((HKEY)(ULONG_PTR)0x80000050)
#define HKEY_PERFORMANCE_NLSTEXT            ((HKEY)(ULONG_PTR)0x80000060)
// this are WINVER > 0x400
#define HKEY_CURRENT_CONFIG                 ((HKEY)(ULONG_PTR)0x80000005)
#define HKEY_DYN_DATA                       ((HKEY)(ULONG_PTR)0x80000006)
#define HKEY_CURRENT_USER_LOCAL_SETTINGS    ((HKEY)(ULONG_PTR)0x80000007)

extern "C" int __stdcall RegOpenKeyExW(HKEY hKey, const wchar_t * pSubName, UINT ulOpts, UINT access, HKEY * phKey);
extern "C" int __stdcall RegGetKeySecurity(HKEY hKey, UINT eSec, void* pSec, UINT * pcbSec);
extern "C" int __stdcall RegEnumKeyExW(HKEY hKey, UINT index, wchar_t * szName, UINT * pcchName, void* res, wchar_t * szClass, UINT * pcchClass, FILETIME * pftLastWrite);
extern "C" int __stdcall RegCloseKey(HKEY hKey);
#define ERROR_NO_MORE_ITEMS  259 // returned by RegEnumKeyEx 


#define BUILD_MODULE_STRING "reg_privs"
#define BUILD_VERSION_STRING "0.1.0"

// a SID consists of 8 bytes, followed by a number of DWORDS
// indicated by the 2nd byte.  (the first byte is the revision)
static bool IsEqualSID(PSID psid1, PSID psid2) {
	const UINT* pdw1 = (const UINT*)psid1;
	const UINT* pdw2 = (const UINT*)psid2;
	if (pdw1[0] != pdw2[0] || pdw1[1] != pdw2[1])
		return false;
	int cSubAs = ((const BYTE*)psid1)[1];
	for (int ix = 0; ix < cSubAs; ++ix) {
		if (pdw1[2+ix] != pdw2[2+ix])
			return false;
	}
	return true;
}

static int CompareMemory(const char * pb1, const char * pb2, int cb) {
	if (cb & 3) {
		for (int ii = 0; ii < cb; ++ii) {
			int diff = pb1[ii] - pb2[ii];
			if (diff) return diff;
		}
	} else {
		const int * pdw1 = (const int *)pb1;
		const int * pdw2 = (const int *)pb2;
		for (int ii = 0; ii < cb/4; ++ii) {
			int diff = pdw1[ii] - pdw2[ii];
			if (diff) return diff;
		}
	}
	return 0;
}

static void CopyMemory(BYTE * pb1, const BYTE * pb2, int cb) {
	while (cb > 0) { *pb1++ = *pb2++; --cb; }
}

static bool IsEqualACE(ACCESS_ACE *pace1, ACCESS_ACE *pace2) {
	int cb1 = pace1->Header.AceSize;
	int cb2 = pace2->Header.AceSize;
	if (cb1 != cb2)
		return false;
	return CompareMemory((char*)pace1, (char*)pace2, cb1) == 0;
}

static int SIDGetMaxTextLength(PSID psid) {
	SID_IDENTIFIER_AUTHORITY * psia = GetSidIdentifierAuthority(psid);
	UINT cSubAs = *GetSidSubAuthorityCount(psid);
	return 6 + 14 + (11 * cSubAs) + 1;
}

static int SIDSizeInBytes(PSID psid) {
	int cSubAs = ((const BYTE*)psid)[1];
	return 8 + (cSubAs * 4);
}

static int FormatGenericAccessMask(UINT fdw, char* buf, int cchMax) {
	static const struct {
		UINT  fdw;
		const char * psz;
	} aBits[] = {
		GENERIC_READ       , "R",            //  0x80000000
		GENERIC_WRITE      , "W",            //  0x40000000
		GENERIC_EXECUTE    , "X",            //  0x20000000
		GENERIC_ALL        , "F",            //  0x10000000

		//STANDARD_RIGHTS_ALL, "All",       //  0x001F0000
		0x000F0000,          "M",         //  MODIFY is RX+Del+CACL+Take
		DELETE_RIGHT       , "D",         //  0x00010000
		READ_CONTROL_RIGHT , "RX",        //  0x00020000
		WRITE_DAC_RIGHT    , "Wac",       //  0x00040000
		WRITE_OWNER_RIGHT  , "Tak",       //  0x00080000
		SYNCHRONIZE_RIGHT  , "Syn",       //  0x00100000
		ACCESS_SYSTEM_SECURITY, "Ass",    //  0x01000000

		KEY_NOTIFY | KEY_CREATE_LINK | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_SET_VALUE | KEY_CREATE_SUB_KEY, "kF",
		KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY, "kR",
		KEY_SET_VALUE | KEY_CREATE_SUB_KEY,                    "kW",

		KEY_QUERY_VALUE        , "kQ", // 0x0001
		KEY_SET_VALUE          , "kW", // 0x0002
		KEY_CREATE_SUB_KEY     , "kC", // 0x0004
		KEY_ENUMERATE_SUB_KEYS , "kT", // 0x0008
		KEY_NOTIFY             , "kN", // 0x0010
		KEY_CREATE_LINK        , "kL", // 0x0020

	};

	char * p = buf;
	char * pe = buf+cchMax;
	for (int ii = 0; ii < NUMELMS(aBits); ++ii) {
		if ((fdw & aBits[ii].fdw) == aBits[ii].fdw) {
			if (ii > 4 && p > buf) p = append(p, ",", pe);
			p = append(p, aBits[ii].psz, pe);
			fdw &= ~aBits[ii].fdw;
		}
	}
	if (fdw) {
		if (p > buf) p = append(p, ",", pe);
		p = append_hex(p,fdw);
	}
	*p = 0;

	return fdw;
}


/*
static LPCSTR GetSidNameUseName(SID_NAME_USE snu) {
	static const char * const aNames[] = {
		"<null>",
		"User",
		"Group",
		"Domain",
		"Alias",
		"WellKnownGroup",
		"DeletedAccount",
		"Invalid",
		"Unknown",
		"Computer",
		"Label"
	};
	if (snu >= 0 && snu < NUMELMS(aNames))
		return aNames[snu];
	return "<bad-snu>";
}
*/

static const char* GetAceTypeName(BYTE AceType) {
	static const char* const aNames[] = {
		"Allow",			//		ACCESS_ALLOWED_ACE_TYPE                 (0x0)
		"Deny",				//		ACCESS_DENIED_ACE_TYPE                  (0x1)
		"Audit",			//		SYSTEM_AUDIT_ACE_TYPE                   (0x2)
		"Alarm",			//		SYSTEM_ALARM_ACE_TYPE                   (0x3)
		"AllowCompound",	//		ACCESS_ALLOWED_COMPOUND_ACE_TYPE        (0x4)
		"AllowObject",		//		ACCESS_ALLOWED_OBJECT_ACE_TYPE          (0x5)
		"DenyObject",		//		ACCESS_DENIED_OBJECT_ACE_TYPE           (0x6)
		"AuditObject",		//		SYSTEM_AUDIT_OBJECT_ACE_TYPE            (0x7)
		"AlarmObject",		//		SYSTEM_ALARM_OBJECT_ACE_TYPE            (0x8)
		"AllowCallback",	//		ACCESS_ALLOWED_CALLBACK_ACE_TYPE        (0x9)
		"DenyCallback",		//		ACCESS_DENIED_CALLBACK_ACE_TYPE         (0xA)
		"AllowCallbackObject",//	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0xB)
		"DenyCallbackObject",//		ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  (0xC)
		"AuditCallback",	//		SYSTEM_AUDIT_CALLBACK_ACE_TYPE          (0xD)
		"AlarmCallback",	//		SYSTEM_ALARM_CALLBACK_ACE_TYPE          (0xE)
		"AuditCallback",	//		SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   (0xF)
		"AlarmCallback",	//		SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   (0x10)
		"ManditoryLabel",	//		SYSTEM_MANDATORY_LABEL_ACE_TYPE         (0x11)
		"ResourceAttribute",//		SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      (0x12)
		"ScopedPolicy",		//		SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        (0x13)
	};
	if (AceType >= 0 && AceType < NUMELMS(aNames))
		return aNames[AceType];
	return "<bad-ace-type>";
}



/*
   int cch = FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS
                           | FORMAT_MESSAGE_FROM_SYSTEM,
                           0, err, 0, 
                           &bp.psz[bp.cch], bp.cchMax - bp.cch,
                           NULL);
*/

wchar_t * GetLastErrorMessage(UINT err, UINT & cch) {
	wchar_t * pwerr = NULL;
	cch = FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, err, 0, (wchar_t*)&pwerr, 0, NULL);
	return pwerr;
}

BOOL PrintLastError(HANDLE hf, unsigned int err, const char* msg, int cargs, wchar_t** pargs) {
	char buf[1024];
	BprintBuffer<char> bp(buf, sizeof(buf), hf);

	bp.formatf("  reg_privs {0:s}", msg);
	if (cargs > 0) {
		for (int ii = 0; ii < cargs; ++ii) {
			bp.formatf(" '{0:w}'", pargs[ii]);
		}
	}
	bp.formatf(" error {0:d}", err);

	UINT cch;
	wchar_t * pwerr = GetLastErrorMessage(err, cch);
	if (pwerr) {
		bp.append(" : ");
		bp.append(pwerr, cch);
		LocalFree((HLOCAL)pwerr);
	}

	bp.EndLine();
	return true;
}

int PrintTokenPrivs(BprintBuffer<char> & bp, HANDLE hToken, const char * pTokenType, bool show_all)
{
	UINT err = 0;
	UINT cbSize = 0;
	if ( ! GetTokenInformation(hToken, TokenPrivileges,  NULL, 0, &cbSize)) {
		err = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER != err)
			goto bail;
	}

	bp.formatfl("The {0} Token is {1:d} bytes", pTokenType, cbSize);
	bp.EndLine();

	void * pvInfo = Alloc(cbSize);
	if ( ! pvInfo) {
		err = ERROR_OUTOFMEMORY;
		goto bail;
	}

	if ( ! GetTokenInformation(hToken, TokenPrivileges,  pvInfo, cbSize, &cbSize)) {
		err = GetLastError();
		goto bail;
	}

	const TOKEN_PRIVILEGES * pPrivs = (const TOKEN_PRIVILEGES *)pvInfo;
	bp.formatfl("The {0} Token has {1:d} privileges", pTokenType, pPrivs->PrivilegeCount);
	bp.EndLine();
	err = 0;

	for (UINT ii = 0; ii < pPrivs->PrivilegeCount; ++ii) {
		if ( ! show_all && ! pPrivs->Privileges[ii].Attributes)
			continue;
		wchar_t szName[260];
		UINT cch = NUMELMS(szName);
		LookupPrivilegeNameW(NULL, &pPrivs->Privileges[ii].Luid, szName, &cch);
		bp.formatfl("  {0:x} {1:w}", pPrivs->Privileges[ii].Attributes, szName);
		bp.EndLine();
	}

bail:
	if (pvInfo) Free(pvInfo);
	if (err) {
		PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "GetTokenInformation", 0, NULL);
	}

	return err;
}

static void BprintSidAlt(BprintBuffer<char> & bp, PSID psid)
{
	WORD * pa = (WORD*)psid;
	if ( ! psid) { bp.append("NULL"); }
	else {
		bp.formatf("sid[{0:x},{1:x},{2:x},{3:x}]", pa[0], pa[1], pa[2], pa[3]);
		UINT cSubs = ((BYTE*)psid)[1];
		UINT * pdw = ((UINT*)psid)+2;
		for (UINT ix = 0; ix < cSubs; ++ix) { bp.formatf("-0x{0:x}", pdw[ix]); }
	}
}

template <class c>
c* append_sid(c* p, PSID psid, c* pe) {
	if ( ! psid) { return append(p, "NULL", pe); }

	SID_IDENTIFIER_AUTHORITY* psia = GetSidIdentifierAuthority(psid);

	p = append(p, "S-", pe);
	p = append_num(p, (UINT)(*(BYTE*)psid));
	p = append(p, "-", pe);

	// authority has two forms, one for pre-defined authorities (where value0 and value1 are 0)
	// and another for general authorities.
	if (psia->Value[0] || psia->Value[1]) {
		p = append(p, "0x", pe);
		for (int ii = 0; ii < 6; ++ii) { p = append_hex(p, (UINT)psia->Value[ii], 2); }
	} else {
		UINT aid = ((UINT)psia->Value[5])
				 + ((UINT)psia->Value[4] <<  8)
				 + ((UINT)psia->Value[3] << 16)
				 + ((UINT)psia->Value[2] << 24);
		p = append_num(p, aid);
	}

	// now append the sub-authorites
	UINT cSubAs = *GetSidSubAuthorityCount(psid);
	for (UINT ix = 0 ; ix < cSubAs; ++ix)  {
		p = append(p, "-", pe);
		p = append_num(p, *GetSidSubAuthority(psid, ix));
	}
	return p;
}

template <class c>
static int BprintSid(BprintBuffer<c> & bp, PSID psid) {
	c* pb = bp.psz+bp.cch;
	c* p = append_sid(pb, psid, bp.psz+bp.cchMax);
	bp.cch += (int)(p - pb);
	return bp.cch;
}

wchar_t * AllocAndInitSidName(PSID psid) {

	wchar_t szDomain[32]; // max domain name is actually 15
	UINT cchDomain = NUMELMS(szDomain);
	wchar_t szName[260];
	UINT cchName = NUMELMS(szName);
	int  snu = 0;

	if ( ! LookupAccountSidW(NULL, psid, szName, &cchName, szDomain, &cchDomain, &snu)) {
		UINT err = GetLastError();
		if (err != ERROR_NONE_MAPPED) {
			append_sid(szName, psid, szName+NUMELMS(szName));
			wchar_t * argv = szName;
			PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "LookupAccountSidW", 1, &argv);
			return NULL;
		}
	}

	wchar_t* sidname = (wchar_t*)Alloc(sizeof(wchar_t)*(cchName + cchDomain + 2));
	wchar_t* p = sidname, *pe = sidname + cchName + cchDomain + 2;
	if (cchDomain) { p = append(p, szDomain, pe); p = append(p, "\\", pe); }
	p = append(p, szName, pe);
	return sidname;
}

const wchar_t* GetCachedSidName(PSID psid, const wchar_t** ptext = NULL) {
	static struct _snci {
		PSID      psid;
		wchar_t * text;
		wchar_t * name;
	} Cache[32];
	static int cCache = 0;

	int ii;
	for (ii = 0; ii < cCache; ++ii) {
		if (IsEqualSID(psid, Cache[ii].psid)) {
			if (ptext) *ptext = Cache[ii].text;
			return Cache[ii].name;
		}
	}
	if (ii < NUMELMS(Cache)) {
		++cCache;
		Cache[ii].psid = AllocCopy((BYTE*)psid, SIDSizeInBytes(psid));
		int cchSid = SIDGetMaxTextLength(psid);
		Cache[ii].text = (wchar_t*)Alloc(cchSid * sizeof(Cache[ii].text[0]));
		append_sid(Cache[ii].text, psid, Cache[ii].text+cchSid);
		Cache[ii].name = AllocAndInitSidName(psid);
		if (ptext) *ptext = Cache[ii].text;
		return Cache[ii].name;
	}

	return NULL;
}

static int BprintACLalt(BprintBuffer<char> & bp, ACL * pacl, UINT cbMax)
{
	if ( ! pacl) { bp.append("NULL"); bp.ToString(); return bp.Count(); }

	bp.formatf("{0:d}-{1:d}-{3:d}/{2:d}-{4:d}",
		pacl->AclRevision,
		pacl->Sbz1,
		pacl->AclSize,
		pacl->AceCount,
		pacl->Sbz2);
	BYTE * pb = ((BYTE*)pacl) + 8;
	BYTE * pbEnd = ((BYTE*)pacl) + pacl->AclSize;
	while (pb < pbEnd) {
		ACE_HEADER *pace = (ACE_HEADER *)pb;
		bp.formatf(" ACE({0:d},{1:d},{2:d})", pace->AceType, pace->AceFlags, pace->AceSize);
		pb += pace->AceSize;
	}
	if (pb != pbEnd) { bp.formatf(" ({0:d} extra", (int)(pbEnd - pb)); }
	bp.ToString();
	return bp.Count();
}

static bool ValidateACL(ACL * pacl, UINT cbMax, UINT & cbActual, UINT & cbClaimed)
{
	if ( ! pacl) { cbActual = cbClaimed = 0; return true; }

	cbClaimed = pacl->AclSize;
	UINT cbRemain = MIN<UINT>(cbMax, pacl->AclSize);
	if (cbRemain < 8) {
		cbActual = 8;
		return false;
	}
	cbRemain -= 8;
	cbActual = 8;
	UINT cRemain = pacl->AceCount;
	BYTE * pb = ((BYTE*)pacl) + 8;
	BYTE * pbEnd = ((BYTE*)pacl) + pacl->AclSize;
	bool valid = true;
	while (pb < pbEnd && cRemain) {
		ACE_HEADER *pah = (ACE_HEADER *)pb;
		if (pah->AceSize < sizeof(ACE_HEADER) || pah->AceSize > cbRemain) {
			valid = false;
		}
		if (pah->AceType > 0x13) {
			valid = false;
		}
		pb += pah->AceSize;
		cbRemain -= pah->AceSize;
		cbActual += pah->AceSize;
		--cRemain;
	}

	return valid;
}

bool ValidateSD(SECURITY_DESCRIPTOR * psd, UINT cbNeeded, UINT& cbClaimed, UINT& cbActual)
{
	//PSID Owner, Group;
	ACL* Sacl, * Dacl;
	UINT cbMaxDacl = -1, cbMaxSacl = -1;

	bool valid = true;
	cbClaimed = cbActual = cbNeeded;

	if (psd->Control & SE_SELF_RELATIVE) {
		SECURITY_DESCRIPTOR_RELATIVE * psdr = (SECURITY_DESCRIPTOR_RELATIVE *)psd;
		//Owner = (PSID)(psdr->Owner ? ((BYTE*)psd) + psdr->Owner : NULL);
		//Group = (PSID)(psdr->Group ? ((BYTE*)psd) + psdr->Group : NULL);
		Sacl = (ACL*)((psdr->Sacl && (psd->Control & SE_SACL_PRESENT)) ? ((BYTE*)psd) + psdr->Sacl : NULL);
		cbMaxSacl =  (psd->Control & SE_SACL_PRESENT) ? (cbNeeded - psdr->Sacl) : 0;
		Dacl = (ACL*)((psdr->Dacl && (psd->Control & SE_DACL_PRESENT)) ? ((BYTE*)psd) + psdr->Dacl : NULL);
		cbMaxDacl =  (psd->Control & SE_DACL_PRESENT) ? (cbNeeded - psdr->Dacl) : 0;

		UINT cbDaclClaimed, cbDaclActual;
		if ( ! ValidateACL(Dacl, cbMaxDacl, cbDaclClaimed, cbDaclActual))  {
			valid = false;
		}
		if (psdr->Dacl > psdr->Sacl && psdr->Dacl > psdr->Owner && psdr->Dacl > psdr->Group) {
			if (cbDaclActual != cbDaclClaimed || cbDaclActual != cbMaxDacl) {
				cbActual = psdr->Dacl + cbDaclActual;
			}
		}
	}
	return valid;
}



static int BprintACL(BprintBuffer<char> & bp, ACL * pacl, UINT cbMax)
{
	if ( ! pacl) { bp.append("NULL"); bp.ToString(); return bp.Count(); }

	//bp.formatf("{0:d}-{1:d}-{3:d}/{2:d}-{4:d}", pacl->AclRevision, pacl->Sbz1, pacl->AclSize, pacl->AceCount, pacl->Sbz2);

	UINT cbRemain = pacl->AclSize; //MIN(cbMax, (UINT)pacl->AclSize);
	if (cbRemain < 8) {
		bp.formatf("malformed ACL, AclSize: {0:d}", pacl->AclSize);
		return bp.StringLength();
	}
	cbRemain -= 8;
	UINT cRemain = pacl->AceCount;
	BYTE * pb = ((BYTE*)pacl) + 8;
	BYTE * pbEnd = ((BYTE*)pacl) + pacl->AclSize;
	while (pb < pbEnd && cRemain) {
		ACE_HEADER *pah = (ACE_HEADER *)pb;
		if (pah->AceSize < sizeof(ACE_HEADER) || pah->AceSize > cbRemain) {
			// uh-oh, this is a malformed
			//break;
		}
		if (pah->AceType == 0 || pah->AceType == 1) {
			ACCESS_ACE * pacc = (ACCESS_ACE*)pah;
			bp.append(pah->AceType ? "Deny" : "Allow");

			char acc[40]; FormatGenericAccessMask(pacc->Mask, acc, NUMELMS(acc));
			bp.formatf(" {0:s} ", acc);
			//bp.formatf(" ({0:x}) ", pacc->Mask);

			BprintSid(bp, &pacc->SidStart);
			const wchar_t * name = GetCachedSidName(&pacc->SidStart);
			if (name) { bp.formatf(" {0:w}", name); }
		} else {
			bp.formatf("ACE({0:d}) size: {1:d}", pah->AceType, pah->AceSize);
		}

		if (pah->AceFlags & OBJECT_INHERIT_ACE) bp.append(" OI");
		if (pah->AceFlags & CONTAINER_INHERIT_ACE) bp.append(" CI");
		if (pah->AceFlags & NO_PROPAGATE_INHERIT_ACE) bp.append(" NI");
		if (pah->AceFlags & INHERIT_ONLY_ACE) bp.append(" IO");
		if (pah->AceFlags & INHERITED_ACE) bp.append(" IA");

		bp.EndLine(false);
		pb += pah->AceSize;
		cbRemain -= pah->AceSize;
		--cRemain;
		if (pb < pbEnd) bp.append("          ");
	}
	if (cbRemain > 0) { 
		bp.formatf("          ({0:d}/{1:p} extra bytes, {2:d} missing ACEs) ", cbRemain, pbEnd - pb, cRemain);
		bp.hex_dump(pb, MIN(cbRemain, (UINT)64), 0, "           ");
		bp.EndLine(false);
	}
	return bp.StringLength();
}

SECURITY_DESCRIPTOR * FetchKeySD(HKEY hkey, UINT eSecInfo, UINT & err, UINT & cbNeeded) {
	void * pvInfo = NULL;
	cbNeeded = 0;
	err = RegGetKeySecurity(hkey, eSecInfo, NULL, &cbNeeded);
	if (err == ERROR_INSUFFICIENT_BUFFER) {
		pvInfo = Alloc(cbNeeded);
		if ( ! pvInfo) {
			err = ERROR_OUTOFMEMORY;
		} else {
			err = RegGetKeySecurity(hkey, eSecInfo, pvInfo, &cbNeeded);
		}
	}
	return (SECURITY_DESCRIPTOR *)pvInfo;
}

int BPrintSD(BprintBuffer<char> & bp, SECURITY_DESCRIPTOR * psd, UINT cbNeeded, int depth, int diagnostic)
{
	if (diagnostic) bp.formatf("acl[{0:d},{1:d},0x{2:x3}]", psd->Revision, psd->Sbz1, psd->Control);

	PSID Owner, Group;
	ACL* Sacl, * Dacl;
	UINT cbMaxDacl = -1, cbMaxSacl = -1;

	if (psd->Control & SE_SELF_RELATIVE) {
		SECURITY_DESCRIPTOR_RELATIVE * psdr = (SECURITY_DESCRIPTOR_RELATIVE *)psd;
		if (diagnostic) { 
			bp.formatf(" {0:d} {1:d}", psdr->Owner, psdr->Group);
			bp.formatf(" {0:d} {1:d}", psdr->Sacl, psdr->Dacl);
		}
		Owner = (PSID)(psdr->Owner ? ((BYTE*)psd) + psdr->Owner : NULL);
		Group = (PSID)(psdr->Group ? ((BYTE*)psd) + psdr->Group : NULL);
		Sacl = (ACL*)((psdr->Sacl && (psd->Control & SE_SACL_PRESENT)) ? ((BYTE*)psd) + psdr->Sacl : NULL);
		cbMaxSacl =  (psd->Control & SE_SACL_PRESENT) ? (cbNeeded - psdr->Sacl) : 0;
		Dacl = (ACL*)((psdr->Dacl && (psd->Control & SE_DACL_PRESENT)) ? ((BYTE*)psd) + psdr->Dacl : NULL);
		cbMaxDacl =  (psd->Control & SE_DACL_PRESENT) ? (cbNeeded - psdr->Dacl) : 0;
	} else {
		if (diagnostic) bp.formatf(" {0:p} {1:p} {2:p} {3:p}", psd->Owner, psd->Group, psd->Sacl, psd->Dacl);
		Owner = psd->Owner;
		Group = psd->Group;
		Sacl = psd->Sacl;
		Dacl = psd->Dacl;
	}

	bp.EndLine();

	bool dOwner = (psd->Control & SE_OWNER_DEFAULTED);
	bp.append(dOwner ? "  dOwner: " : "  Owner:  "); BprintSid(bp, Owner);
	if (Owner) {
		const wchar_t * sidname = GetCachedSidName(Owner);
		if (sidname) bp.formatf(" {0:w}", sidname);
	}
	bp.EndLine();

	bool dGroup = (psd->Control & SE_GROUP_DEFAULTED);
	bp.append(dGroup ? "  dGroup: " : "  Group:  "); BprintSid(bp, Group);
	if (Group) {
		const wchar_t * sidname = GetCachedSidName(Group);
		if (sidname) bp.formatf(" {0:w}", sidname);
	}
	bp.EndLine();

	bool aiSacl = (psd->Control & SE_SACL_AUTO_INHERITED);
	bp.append(aiSacl ? "  iSacl:  " : "  Sacl:   "); BprintACL(bp, Sacl, cbMaxSacl);
	bp.EndLine();

	bool aiDacl = (psd->Control & SE_DACL_AUTO_INHERITED);
	bp.append(aiDacl ? "  iDacl:  " : "  Dacl:   "); BprintACL(bp, Dacl, cbMaxDacl);
	bp.EndLine();

	return bp.StringLength();
}

template <class c>
class PathBuffer {
public:
	c*  buf;
	int cchMax;
	int ixp;
	bool owns_buffer; 
	PathBuffer(c* full=NULL, int cch=0) : buf(full), cchMax(cch), ixp(0), owns_buffer(false) { }
	~PathBuffer() { if (owns_buffer && buf) Free(buf); buf = NULL; }
	c* alloc_buffer(int cch) {
		cchMax = cch; ixp = 0; owns_buffer = true;
		buf = Alloc<c>(cchMax);
		buf[0] = buf[1] = 0;
		return buf;
	}
	//c* subname() { if (buf[ixp] == '\\') { return &buf[ixp+1]; } else { return buf; } }
	c* subname() { return &buf[ixp+1]; }
	int max_subname() { return (int)(buf+cchMax - subname()); }
	const c* to_fullname() { if (ixp) buf[ixp] = '\\'; return buf; }
	const c* to_splitname() { if (ixp) buf[ixp] = 0; return buf; }
	const c* set_basename(const c* base, int cchBase) { 
		if (cchBase < 0) cchBase = Length(base);
		if (cchBase >= cchMax) __debugbreak();
		CopyText(buf, cchMax, base, cchBase);
		ixp = cchBase;
		if (ixp > 0 && (buf[ixp-1] == '\\' || buf[ixp-1] == '/')) { --ixp; }
		buf[ixp+1] = buf[ixp] = 0;
		return buf;
	}
	const c* set_pathend(c* pe) {
		c* per = buf+ixp;
		if (pe >= buf && pe < buf + cchMax) {
			pe[0] = pe[1] = 0;
			ixp = (int)(pe - buf);
		}
		return per;
	}
	c* decend() { 
		c* per = buf+ixp;
		*per = '\\';
		int cch = Length(per);
		if (cch > 1) {
			ixp += cch;
			buf[ixp] = '\\';
		}
		return per;
	}
};

SECURITY_DESCRIPTOR_RELATIVE * CopyToNewSelfRelativeSD(SECURITY_DESCRIPTOR * psd, UINT * pcbsd)
{
	PSID Owner = psd->Owner, Group = psd->Group;
	ACL* Sacl = psd->Sacl, * Dacl = psd->Dacl;
	int cbOwner = Owner ? SIDSizeInBytes(Owner) : 0;
	int cbGroup = Group ? SIDSizeInBytes(Group) : 0;
	int cbSacl = (Sacl && (psd->Control & SE_SACL_PRESENT)) ? Sacl->AclSize : 0;
	int cbDacl = (Dacl && (psd->Control & SE_DACL_PRESENT)) ? Dacl->AclSize : 0;
	int cb = sizeof(SECURITY_DESCRIPTOR_RELATIVE) + cbOwner + cbGroup + cbSacl + cbDacl;

	SECURITY_DESCRIPTOR_RELATIVE * sdr = (SECURITY_DESCRIPTOR_RELATIVE * )AllocZero(cb);
	sdr->Revision = psd->Revision;
	sdr->Sbz1 = psd->Sbz1;
	sdr->Control = psd->Control | SE_SELF_RELATIVE;

	UINT ix = sizeof(SECURITY_DESCRIPTOR_RELATIVE);
	if (Owner) {
		sdr->Owner = ix;
		CopyMemory((BYTE*)sdr+sdr->Owner, (BYTE*)Owner, cbOwner);
		ix += cbOwner;
	}
	if (Group) {
		sdr->Group = ix;
		CopyMemory((BYTE*)sdr+sdr->Group, (BYTE*)Group, cbGroup);
		ix += cbGroup;
	}
	if (Sacl && cbSacl) {
		sdr->Sacl = ix;
		CopyMemory((BYTE*)sdr+sdr->Sacl, (BYTE*)Sacl, cbSacl);
		ix += cbSacl;
	}
	if (Dacl && cbDacl) {
		sdr->Dacl = ix;
		CopyMemory((BYTE*)sdr+sdr->Dacl, (BYTE*)Dacl, cbDacl);
		ix += cbDacl;
	}
	if (pcbsd) *pcbsd = cb;
	return sdr;
}


struct _sdci {
	SECURITY_DESCRIPTOR * psd;
	UINT                  cbsd;
	UINT                  cbactual;
	UINT                  hits;
	UINT                  flags;
	wchar_t *             name;
};
#define SDCI_F_ABS        0x0001
#define SDCI_F_ABS_HIT    0x0002
#define SDCI_F_INVALID    0x0004
#define SDCI_F_EXTRAJUNK  0x0008

const LONG_PTR GetCachedSD_UID(SECURITY_DESCRIPTOR * psd, UINT cbsd, wchar_t * name) {
	static struct _sdci Cache[1000];
	static int cCache = 0;

	// as a hack, a null psd means they want to retrieve cache lines.
	if ( ! psd) {
		if (cbsd < (UINT)cCache) return (LONG_PTR)(ULONG_PTR)&Cache[cbsd];
		return 0;
	}

	SECURITY_DESCRIPTOR_RELATIVE * sdr = NULL;
	if ( ! (psd->Control & SE_SELF_RELATIVE)) {
		sdr = CopyToNewSelfRelativeSD(psd, &cbsd);
		psd = (SECURITY_DESCRIPTOR *)sdr;
	}

	int ii;
	for (ii = 0; ii < cCache; ++ii) {
		if (cbsd == Cache[ii].cbsd && 0 == CompareMemory((const char*)psd, (const char*)Cache[ii].psd, cbsd)) {
			Cache[ii].hits += 1;
			if (sdr) Cache[ii].flags |= SDCI_F_ABS_HIT;
			Free(sdr);
			return ii;
		}
	}
	if (ii < NUMELMS(Cache)) {
		++cCache;
		Cache[ii].flags = 0;
		Cache[ii].hits = 0;
		if (sdr) {
			Cache[ii].flags |= SDCI_F_ABS;
			Cache[ii].psd = psd;
			sdr = NULL;
		} else {
			Cache[ii].psd = (SECURITY_DESCRIPTOR *)AllocCopy((BYTE*)psd, cbsd);
		}
		Cache[ii].name = AllocCopy(name, Length(name)+1);
		Cache[ii].cbactual = Cache[ii].cbsd = cbsd;
		UINT cbClaimed, cbActual;
		if ( ! ValidateSD(psd, cbsd, cbClaimed, cbActual)) {
			Cache[ii].flags |= SDCI_F_INVALID;
		} else if (cbActual < cbsd) {
			Cache[ii].cbactual = cbActual;
			Cache[ii].flags |= SDCI_F_EXTRAJUNK;
		}
		return ii;
	}
	if (sdr) Free(sdr);
	return (LONG_PTR)-1;
}

int PrintRegKeySDUniqueness(void*pv, BprintBuffer<char> & bp, HKEY hkey, PathBuffer<wchar_t> & path, int depth, bool verbose, int diagnostic)
{
	UINT err = 0;
	const UINT eSecInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
	UINT cbNeeded = 0;
	SECURITY_DESCRIPTOR * psd = FetchKeySD(hkey, eSecInfo, err, cbNeeded);
	if (err) {
		PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "RegGetKeySecurity", 1, const_cast<wchar_t**>(&path.buf));
	} else {
		if (diagnostic) bp.printfl("Got {0:d} bytes of DACL info from {1:w}", cbNeeded, path.subname());
		int uid = GetCachedSD_UID(psd, cbNeeded, path.buf);
		bp.printfl("{0,4:d} {1:w}", uid, path.buf);

		Free(psd);
	}
	return err;
}

int PrintRegKeyNameIfSDNotInherited(void*pv, BprintBuffer<char> & bp, HKEY hkey, PathBuffer<wchar_t> & path, int depth, bool verbose, int diagnostic)
{
	UINT err = 0;
	const UINT eSecInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
	UINT cbNeeded = 0;
	SECURITY_DESCRIPTOR * psd = FetchKeySD(hkey, eSecInfo, err, cbNeeded);
	if (err) {
		PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "RegGetKeySecurity", 1, const_cast<wchar_t**>(&path.buf));
	} else {
		if (diagnostic) bp.printfl("Got {0:d} bytes of DACL info from {1:w}", cbNeeded, path.subname());
		if ( ! (psd->Control & SE_DACL_AUTO_INHERITED)) {
			if ( ! verbose) { bp.printl(path.buf); } // because traverse didn't
			if (verbose) { BPrintSD(bp, psd, cbNeeded, depth, diagnostic); }
		}
		Free(psd);
	}
	return err;
}

int PrintRegKeySDifNotInherited(void*pv, BprintBuffer<char> & bp, HKEY hkey, PathBuffer<wchar_t> & path, int depth, bool verbose, int diagnostic)
{
	UINT err = 0;
	const UINT eSecInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
	UINT cbNeeded = 0;
	SECURITY_DESCRIPTOR * psd = FetchKeySD(hkey, eSecInfo, err, cbNeeded);
	if (err) {
		PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "RegGetKeySecurity", 1, const_cast<wchar_t**>(&path.buf));
	} else {
		if (diagnostic) bp.printfl("Got {0:d} bytes of DACL info from {1:w}", cbNeeded, path.subname());
		if ( ! (psd->Control & SE_DACL_AUTO_INHERITED)) {
			if ( ! verbose) { bp.printl(path.buf); } // because traverse didn't
			BPrintSD(bp, psd, cbNeeded, depth, diagnostic);
		}
		Free(psd);
	}
	return err;
}

int PrintRegKeySD(void*pv, BprintBuffer<char> & bp, HKEY hkey, PathBuffer<wchar_t> & path, int depth, bool verbose, int diagnostic)
{
	UINT err = 0;
	const UINT eSecInfo = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
	UINT cbNeeded = 0;
	SECURITY_DESCRIPTOR * psd = FetchKeySD(hkey, eSecInfo, err, cbNeeded);
	if (err) {
		PrintLastError(GetStdHandle(STD_ERR_HANDLE), err, "RegGetKeySecurity", 1, const_cast<wchar_t**>(&path.buf));
	} else {
		if (diagnostic) bp.printfl("Got {0:d} bytes of DACL info from {1:w}", cbNeeded, path.subname());
		if ( ! verbose) { bp.printl(path.buf); } // because traverse didn't
		BPrintSD(bp, psd, cbNeeded, depth, diagnostic);
		Free(psd);
	}
	return err;
}

HKEY InitRegKeyPath(PathBuffer<wchar_t> & path, const wchar_t * fullname)
{
	path.set_basename(fullname, -1); // this removes any trailing \ and sets path.pathend to the end of the string
	const wchar_t * name = path.buf;

	HKEY hroot = HKEY_CLASSES_ROOT;
	     if (str_starts_with_nocase(name, L"HKLM")) { hroot =  HKEY_LOCAL_MACHINE; name += 4; }
	else if (str_starts_with_nocase(name, L"HKCR")) { hroot =  HKEY_CLASSES_ROOT; name += 4; }
	else if (str_starts_with_nocase(name, L"HKCU")) { hroot =  HKEY_CURRENT_USER; name += 4; }
	else if (str_starts_with_nocase(name, L"HKU"))  { hroot =  HKEY_USERS; name += 3; }
	else if (str_starts_with_nocase(name, L"HKCC")) { hroot =  HKEY_CURRENT_CONFIG; name += 4; }
	else if (str_starts_with_nocase(name, L"HKPD")) { hroot =  HKEY_PERFORMANCE_DATA; name += 4; }

	if (*name == '\\' || *name == 0) { path.ixp = (int)(name - path.buf); }
	else { hroot = HKEY_CLASSES_ROOT; path.ixp = 0; }
	return hroot;
}

typedef int (*FN_TRAVERSE_CALLBACK)(void*pv, BprintBuffer<char> & bp, HKEY hkey, PathBuffer<wchar_t> & path, int depth, bool verbose, int diagnostic);
int TraverseRegKey(
	BprintBuffer<char> & bp,
	HKEY hroot,
	PathBuffer<wchar_t> & path,
	int depth, int max_depth, bool verbose, int diagnostic,
	UINT other_access,
	FN_TRAVERSE_CALLBACK pfn,
	void* pv)
{
	int err = 0;
	if (verbose) { bp.printl(path.buf); }
	if (pfn) err = pfn(pv, bp, hroot, path, depth, verbose, diagnostic);
	if (depth >= max_depth) { return err; }

	wchar_t * per = path.decend();
	wchar_t * subname = path.subname();
	UINT cchMaxSub = path.max_subname();

	UINT keybitness = 0;
	UINT access = STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | other_access;
	for (int index = 0; index < 10000000; ++index) {

		UINT cchSubname = cchMaxSub;
		int lres = RegEnumKeyExW(hroot, index, subname, &cchSubname, NULL, NULL, NULL, NULL);
		if (ERROR_NO_MORE_ITEMS == lres)
			break;

		path.to_fullname(); // make sure path separator is in place
		if (diagnostic) {
			bp.formatfl(" {3:m}+-- '{0:w}' {1:d} {2:d}", subname, per - path.buf, subname - path.buf, depth*2);
		}

		HKEY hkey;
		lres = RegOpenKeyExW(hroot, subname, 0, access | keybitness, &hkey);
		if (lres) {
			bp.formatf("{0:w} RegOpenKeyEx error {1:d}", path.buf, lres);
			UINT cch;
			wchar_t * pwerr = GetLastErrorMessage(lres, cch);
			if (pwerr) {
				bp.append(" : ");
				bp.append(pwerr, cch);
				LocalFree((HLOCAL)pwerr);
			}
			bp.EndLine();
			if (pfn) err = pfn(pv, bp, hkey, path, depth, verbose, diagnostic);
			continue;
		}
		err = TraverseRegKey(bp, hkey, path, depth+1, max_depth, verbose, diagnostic, other_access, pfn, pv);
		RegCloseKey(hkey);
	}

	path.set_pathend(per);

	return err;
}


struct _argitem {
	struct _argitem * next;
	wchar_t arg[1];
};
struct _arglist {
	struct _argitem * head;
	struct _argitem * last;
	void append(struct _argitem * pai) {
		if (this->last) { this->last->next = pai; }
		if ( ! this->head) { this->head = pai; }
		while (pai->next) pai = pai->next;
		this->last = pai;
	}
	void push(struct _argitem * pai) {
		struct _argitem * pae = pai;
		while (pae->next) pae = pae->next;
		if (this->head) { pae->next = this->head; }
		this->head = pai;
		if ( ! this->last) { this->last = pae; }
	}
	struct _argitem * pop() {
		struct _argitem * pai = this->head;
		if (this->head) { this->head = this->head->next; }
		if ( ! this->head) { this->last = NULL; }
		return pai;
	}
	struct _argitem * append(const wchar_t* pArg, int cch) {
		if (cch < 0) { cch = Length(pArg); }
		struct _argitem * pai = (struct _argitem *)AllocZero( sizeof(struct _argitem) + (cch) * sizeof(pArg[0]) );
		if (pai) {
			if (pArg) { for (int ii = 0; ii < cch; ++ii) { pai->arg[ii] = pArg[ii]; } }
			pai->next = NULL;
		}
		this->append(pai);
		return pai;
	}
};

extern "C" void __cdecl begin( void )
{
	int show_usage = 0;
	int dash_verbose = 0;
	int dash_append_mode = 0;
	int dash_diagnostic = 0;
	int dash_recursive = 0;
	int next_arg_is = 0; // 'e' = file, 't' = timeout
	int was_key = 0;
	int return_code = 0;
	struct _arglist keyargs = {NULL,NULL};

	HANDLE hJob = NULL;
	HANDLE hStdOut = GetStdHandle(STD_OUT_HANDLE);
	HANDLE hStdErr = GetStdHandle(STD_ERR_HANDLE);

	const char * ws = " \t\r\n";
	const wchar_t * pwholecmdline = GetCommandLineW();
	const wchar_t * pcmdline = next_token(pwholecmdline, ws); // get command line and skip the command name.
	while (*pcmdline) {
		int cchArg;
		const wchar_t * pArg;
		const wchar_t * pnext = next_token_ref(pcmdline, ws, pArg, cchArg);
		if (next_arg_is) {
			switch (next_arg_is) {
				/*
			 case 'e':
				env_filename = AllocCopyZ(pArg, cchArg);
				break;
				*/
			 default: return_code = show_usage = 1; break;
			}
			next_arg_is = 0;
		} else if (*pArg == '-' || *pArg == '/') {
			const wchar_t * popt = pArg+1;
			for (int ii = 1; ii < cchArg; ++ii) {
				wchar_t opt = pArg[ii];
				switch (opt) {
				 case 'h': show_usage = 1; break;
				 case '?': show_usage = 1; break;
				 case 'v': dash_verbose = 1; break;
				 case 'a': dash_append_mode = 1; break;
				 case 'd': dash_diagnostic = 1; break;
				 case 'r': dash_recursive = 1; break;

				//case 'e':
				//	next_arg_is = opt;
				//	break;
				 default:
					return_code = show_usage = 1;
					break;
				}
			}
		} else if (*pArg) {
			was_key = 1;
			keyargs.append(pArg, cchArg);
		}
		pcmdline = pnext;
	}

	if (show_usage || ! was_key) {
		Print(return_code ? hStdErr : hStdOut,
			BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\r\n"
			"\r\nUsage: " BUILD_MODULE_STRING " [options] <regkey>\r\n\r\n"
			"    open <regkey> and show/modify the security ACLs on it\r\n"
			"\r\n  [options] are\r\n\r\n"
			"   -h or -?  print usage (this output)\r\n"
			"   -r        recurse\r\n"
			//"   -a        open output files in append mode (ignored if -o is not used)\r\n"
			"   -v        verbose mode. Prints parsed args to stdout before executing\r\n"
			"   -d        diagnostic mode\r\n"
			"\r\n" , -1);
	} else {

		int cchBuf = Length(pwholecmdline) + 65000;
		char *buffer = (char*)Alloc(cchBuf);
		BprintBuffer<char> bp(buffer, cchBuf, hStdOut);
		if (dash_verbose) {

			/*
			append(bp, "Arguments\r\n\tCommand: '");
			if (command) { append(bp, command); }
			append(bp, "'\n");
			bp.Print(hStdErr);

			append(bp, "\tOutput: '");
			if (output_filename) { append(bp, output_filename); }
			append(bp, "'\n");
			bp.Print(hStdErr);
			append(bp, "\tError: '");
			if (error_filename) { append(bp, error_filename); }
			append(bp, "'\n");
			bp.Print(hStdErr);

			if (has_timeout) {
				append(bp, "\tTimeout: ");
				append_num(bp, msTimeout);
				append(bp, " (ms)\n");
				bp.Print(hStdErr);
			}

			append(bp, "\tOptions: ");
			append(bp, dash_new_group ? "New Ctrl Group, " : "");
			if (dash_dump_on_timout) { append(bp, " Dump PIDs on timeout");
				if (msWaitAfterPidDump) { append(bp, " and wait "); append_num(bp, msWaitAfterPidDump); append(bp, " ms"); }
				append(bp, ", ");
			}
			append(bp, dash_kill ? "Kill" : (dash_ctrl_brk ? "Ctrl+Break" : "Ctrl+C"));
			append(bp, "\n");
			bp.Print(hStdErr);

			append(bp, "\tEnvironment File: '"); 
			if (env_filename) { append(bp, env_filename); } else { append(bp, "NULL"); }
			append(bp, "'\n");
			bp.Print(hStdErr);

			if (env_dump_filename) {
				append(bp, "\tEnvironment Dump File: '"); 
				if (env_dump_filename) { append(bp, env_dump_filename); }
				append(bp, "'\n");
				bp.Print(hStdErr);
			}
			*/
		}

		HANDLE hToken = NULL;
		const char * pTokenType = "Thread";
		if ( ! OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, true, &hToken)) {
			UINT err = GetLastError();
			if (err != ERROR_NO_TOKEN) { PrintLastError(hStdErr, err, "failed to OpenThreadToken", 0, NULL); }
			hToken = NULL;
			pTokenType = "Process";
			if ((err == ERROR_NO_TOKEN) && ! OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken)) {
				PrintLastError(hStdErr, GetLastError(), "failed to OpenProcessToken", 0, NULL);
				hToken = NULL;
			}
			if ( ! hToken || hToken == INVALID_HANDLE_VALUE)
				ExitProcess(1);
		}

		if (dash_diagnostic) {
			//bp.printfl("got {0} token {1:p}", pTokenType, hToken);
			//PrintTokenPrivs(bp, hToken, pTokenType, true);
			bp.printfl("\nAdjusting token privileges to allow querying and changing ACLs");
		}

		bool enable_priv = true;
		static const wchar_t * const needed_privs[] = { SE_SECURITY_NAME, SE_TAKE_OWNERSHIP_NAME, };
		struct {
			TOKEN_PRIVILEGES hd;
			LUID_AND_ATTRIBUTES addl[64];
		} tp = {0};
		tp.hd.PrivilegeCount = NUMELMS(needed_privs);
		for (int ix = 0; ix < NUMELMS(needed_privs); ++ix) {
			LUID luid;
			if ( ! LookupPrivilegeValueW(NULL, needed_privs[ix], &luid)) {
				PrintLastError(hStdErr, GetLastError(), "failed to LookupPrivilegeValue", 1, const_cast<wchar_t**>(&needed_privs[ix]));
				ExitProcess(1);
			}
			tp.hd.Privileges[ix].Luid = luid;
			tp.hd.Privileges[ix].Attributes = (enable_priv) ? SE_PRIVILEGE_ENABLED : 0;
		}

		if ( ! AdjustTokenPrivileges(hToken, false, &tp.hd, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
			PrintLastError(hStdErr, GetLastError(), "failed to AdjustTokenPrivileges", 0, NULL);
			ExitProcess(1);
		}

		if (dash_diagnostic) {
			PrintTokenPrivs(bp, hToken, pTokenType, false);
			bp.printfl(" ");
		}

		//FN_TRAVERSE_CALLBACK pfn = PrintRegKeySD;
		FN_TRAVERSE_CALLBACK pfn = PrintRegKeySD;
		pfn = PrintRegKeySDifNotInherited;
		pfn = PrintRegKeyNameIfSDNotInherited;
		pfn = PrintRegKeySDUniqueness;
		UINT other_access = ACCESS_SYSTEM_SECURITY;

		PathBuffer<wchar_t> path;
		path.alloc_buffer(4096); // set max registry key path depth

		for (struct _argitem * pai = keyargs.pop(); pai; pai = keyargs.pop()) {
			if (dash_diagnostic) { bp.printfl("Quering {0:w}{1:s}", pai->arg, dash_recursive ? " and child keys" : ""); }

			HKEY hroot = InitRegKeyPath(path, pai->arg);
			//if (dash_diagnostic) { bp.printfl("path = {0:p},{1:d},{2:d} ={3:d}", path.buf, path.ixp, path.cchMax, path.buf[path.ixp]); }

			UINT keybitness = 0;
			UINT access = STANDARD_RIGHTS_READ | KEY_ENUMERATE_SUB_KEYS | other_access;
			HKEY hkey = NULL;
			const wchar_t * name = path.subname();
			//if (dash_diagnostic) { bp.printfl("subname = {0:p},{1:d},{2:d} ={3:d}", name, path.ixp, path.cchMax, *name); }
			if (*name) {
				int lres = RegOpenKeyExW(hroot, name, 0, access | keybitness, &hkey);
				if (lres) { PrintLastError(hStdErr, lres, "RegOpenKeyEx", 1, const_cast<wchar_t**>(&name)); hkey = NULL; }
			} else {
				hkey = hroot;
			}

			if (hkey) {
				TraverseRegKey(bp, hkey, path, 0, dash_recursive ? 0xFFFF : 0, dash_verbose, dash_diagnostic, other_access, pfn, NULL);
				if (hkey != hroot) RegCloseKey(hkey); hkey = NULL;
			}
			Free(pai);
		}

		struct _sdci * pci = (struct _sdci *)GetCachedSD_UID(NULL, 0, NULL);
		if (pci) {
			bp.printl("\nUnique SDs:");
			UINT uid = 0;
			UINT cSingles = 0, cFlags = 0;
			UINT cbMinSingle = 0xFFFFFFFF, cbMaxSingle = 0;
			do {
				bp.printfl("{0,4:d} {1:w}", uid, pci->name ? pci->name : L"?");
				BPrintSD(bp, pci->psd, pci->cbsd, 0, dash_diagnostic);
				bp.EndLine();

				// gather singleton stats.
				if ( ! pci->hits) {
					++cSingles;
					cbMinSingle = MIN(cbMinSingle, pci->cbsd);
					cbMaxSingle = MAX(cbMaxSingle, pci->cbsd);
				}
				if (pci->flags) {
					++cFlags;
				}
			} while ( (pci = (struct _sdci *)GetCachedSD_UID(NULL, ++uid, NULL)) );

			// now print a summary
			uid = 0;
			pci = (struct _sdci *)GetCachedSD_UID(NULL, 0, NULL);
			bp.printfl("\nSD Use Stats:\n{0,4} {1,6} {2,6} {3,6} {4,6} {5}", "Item", "Size", "Actual", "flags", "Hits", "First-Use-Key");
			do {
				if (pci->hits) {
					bp.formatf("{0,4:d}", uid);
					bp.formatf(" {0,6:d}", pci->cbsd);
					bp.formatf(" {0,6:d}", pci->cbactual);
					bp.formatf(" {0,6:x}", pci->flags);
					bp.formatf(" {0,6:d} ", pci->hits);
					bp.appendl(pci->name ? pci->name : L"");
				}
			} while ( (pci = (struct _sdci *)GetCachedSD_UID(NULL, ++uid, NULL)) );

			if (cSingles) {
				bp.formatf(" + {0:d} singletons", cSingles);
				bp.printfl(" with sizes from {0:d} to {1:d}", cbMinSingle, cbMaxSingle);
			}
			if (cFlags) {
				bp.formatf(" and {0:d} flagged ACLs", cFlags);
				bp.EndLine();
			}
		}


		if (hToken && hToken != INVALID_HANDLE_VALUE) CloseHandle(hToken); hToken = NULL;
	}

	ExitProcess(return_code);
}
