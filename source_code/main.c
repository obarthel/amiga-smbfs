/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2019 by Olaf `Olsen' Barthel <obarthel -at- gmx -dot- net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * cpr smbfs.debug domain=workgroup user=olsen password=... volume=olsen //felix/olsen
 * cpr smbfs.debug dumpsmb user=guest volume=amiga //windows7-amiga/Users/Public
 * smbfs debuglevel=2 debugfile=ram:windows7.log user=guest volume=amiga //windows7-amiga/Users/Public
 * copy "amiga:Public/Documents/Amiga Files/Shared/dir/Windows-Export/LP2NRFP.h" ram:
 * smbfs.debug user=guest volume=sicherung //192.168.1.76/sicherung-smb
 * smbfs maxtransmit=16600 debuglevel=2 dumpsmb dumpsmblevel=2 domain=workgroup user=olsen password=... volume=olsen //felix/olsen
 * Fritz!Box: smbfs debuglevel=2 debugfile=ram:fritz.nas.log user=nas password=nas volume=fritz.nas //fritzbox-3272/fritz.nas
 * Samba 4.6.7: smbfs debuglevel=2 debugfile=ram:ubuntu-17.log volume=ubuntu-test //ubuntu-17-olaf/test
 * Samba 4.7.6: smbfs debuglevel=2 debugfile=ram:ubuntu-18.log volume=ubuntu-test //ubuntu-18-olaf/test
 * Samba 3.0.25: smbfs debuglevel=2 debugfile=ram:samba-3.0.25.log user=olsen password=... volume=olsen //192.168.1.118/olsen
 *
 * diskspeed drive olsen:Documents dir seek fast byte nocpu
 */

#include "smbfs.h"

/****************************************************************************/

#include "smb_abstraction.h"
#include "cp437.h"
#include "cp850.h"
#include "errors.h"
#include "quad_math.h"
#include "dump_smb.h"

/****************************************************************************/

#include <smb/smb_fs_sb.h>
#include <smb/smb_fs.h>
#include <smb/smbno.h>
#include <smb/smb.h>

/****************************************************************************/

#include "smbfs_rev.h"
TEXT Version[] = VERSTAG;

/****************************************************************************/

/* The fully optimized build for SAS/C needs the following
 * definition because it uses the so-called "small data model"
 * for accessing local program data.
 */
#if defined(__SASC) && DEBUG == 0
#define SAVE_DS __saveds
#else
#define SAVE_DS
#endif /* __SASC && !DEBUG */

/****************************************************************************/

/* This macro lets us long-align structures on the stack */
#define D_S(type, name) \
	UBYTE a_##name[sizeof(type) + 3]; \
	type * name = (type *)((ULONG)(a_##name + 3) & ~3UL)

/****************************************************************************/

/* Difference between January 1st 1970 and January 1st 1978 in seconds,
 * which is needed because the Amiga system time base uses 1978 and we
 * have to deal with Unix time information.
 */
#define UNIX_TIME_OFFSET 252460800

/* Maximum length of a file name, as supported by AmigaDOS. */
#define MAX_FILENAME_LEN 255

/****************************************************************************/

/* This is the root of the SMB directory path, sort of like the
 * equivalent to ":" as used with AmigaDOS.
 */
#define SMB_ROOT_DIR_NAME	"\\"

/* Individual directory/file names are separated by the backslash for SMB
 * path names (actually, SMB uses the MS-DOS path separator). AmigaDOS
 * uses the slash.
 */
#define SMB_PATH_SEPARATOR	'\\'

/****************************************************************************/

/* This is for use with the ReadArgs() argument processing. */
typedef STRPTR	KEY;		/* PARAMETER/K, /A, /F */
typedef LONG *	NUMBER;		/* PARAMETER/N */
typedef LONG	SWITCH;		/* PARAMETER/S */

/****************************************************************************/

/* The internal data structure which ties an AmigaDOS FileHandle to the
 * smbfs representation.
 */
struct FileNode
{
	struct MinNode		fn_MinNode;

	#ifdef USE_SPLAY_TREE

	struct splay_node	fn_SplayNameNode;
	struct splay_node	fn_SplayAddressNode;

	#endif /* USE_SPLAY_TREE */

	ULONG				fn_Magic;		/* Magic number which helps to
										 * identify this data structure
										 * as being managed by smbfs.
										 * We use this as a safety measure
										 * in case smbfs receives a file
										 * handle that it did not create.
										 */

	struct DosList *	fn_Volume;		/* Points back to the volume which
										 * the file is associated with.
										 */

	struct FileHandle *	fn_Handle;		/* The AmigaDOS file handle which
										 * this data structure is associated
										 * with.
										 */

	QUAD				fn_OffsetQuad;	/* Current file read/write position,
										 * as an unsigned 64 bit integer.
										 */
	LONG				fn_Mode;		/* File access mode, e.g. MODE_NEWFILE,
										 * MODE_OLDFILE, MODE_READWRITE.
										 */

	smba_file_t *		fn_File;		/* The SMB file system interface to
										 * the remote file.
										 */
	STRPTR				fn_FullName;	/* The name of the file at the time
										 * it was opened. Note that this
										 * includes the full path, using the
										 * SMB path syntax.
										 */
};

/****************************************************************************/

/* The internal data structure which ties an AmigaDOS FileLock to the
 * smbfs representation. smbfs creates this and returns a pointer to
 * the ln_FileLock member.
 */
struct LockNode
{
	struct MinNode			ln_MinNode;

	#ifdef USE_SPLAY_TREE

	struct splay_node		ln_SplayNameNode;
	struct splay_node		ln_SplayAddressNode;

	#endif /* USE_SPLAY_TREE */

	ULONG					ln_Magic;	/* Magic number which helps to
										 * identify this data structure
										 * as being managed by smbfs.
										 * We use this as a safety measure
										 * in case smbfs receives a file
										 * lock that it did not create.
										 */

	struct FileLock			ln_FileLock;
										/* The AmigaDOS file lock which this
										 * data structure is associated with.
										 */

	smba_file_t *			ln_File;	/* The SMB file system interface to
										 * the remote file or directory.
										 */
	STRPTR					ln_FullName;
										/* The name of the file or directory
										 * at the time it was accessed. Note
										 * that this includes the full path,
										 * using the SMB path syntax.
										 */

	const struct MsgPort *	ln_LastUser;
										/* This identifies the last Process
										 * which used this file lock. We need
										 * this to handle deleting from a
										 * directory and scanning that directory
										 * at the same time more smoothly.
										 */

	BOOL					ln_RestartExamine;
										/* If this a file lock on a directory,
										 * this flag states if directory
										 * scanning in progress needs to
										 * start over.
										 */
};

/****************************************************************************/

/* The minimum operating system version we require to work. */
#define MINIMUM_OS_VERSION 37		/* Kickstart 2.04 or better */
/*#define MINIMUM_OS_VERSION 39*/	/* Kickstart 3.0 or better */

/****************************************************************************/

/* Careful: the memory pool routines in amiga.lib are available only to
 *          SAS/C and similar compilers (not necessarily to GCC).
 */
#if defined(__GNUC__) && (MINIMUM_OS_VERSION < 39)

#undef MINIMUM_OS_VERSION
#define MINIMUM_OS_VERSION 39

#endif /* __GNUC__ */

/****************************************************************************/

/* If possible, we want to use the memory pool functions in amiga.lib rather
 * than those in ROM. The V37 build has to include these in the program itself
 * since Kickstart 2.04 lacks them.
 */
#if (MINIMUM_OS_VERSION < 39)

/* These are in amiga.lib */
APTR ASM AsmCreatePool(REG(d0,ULONG memFlags),REG(d1,ULONG puddleSize),REG(d2,ULONG threshSize),REG(a6,struct Library * SysBase));
void ASM AsmDeletePool(REG(a0,APTR poolHeader),REG(a6,struct Library * SysBase));
APTR ASM AsmAllocPooled(REG(a0,APTR poolHeader),REG(d0,ULONG memSize),REG(a6,struct Library * SysBase));
void ASM AsmFreePooled(REG(a0,APTR poolHeader),REG(a1,APTR memory),REG(d0,ULONG memSize),REG(a6,struct Library * SysBase));

#define CreatePool(memFlags,puddleSize,threshSize) AsmCreatePool((memFlags),(puddleSize),(threshSize),SysBase)
#define DeletePool(poolHeader) AsmDeletePool((poolHeader),SysBase)
#define AllocPooled(poolHeader,memSize) AsmAllocPooled((poolHeader),(memSize),SysBase)
#define FreePooled(poolHeader,memory,memSize) AsmFreePooled((poolHeader),(memory),(memSize),SysBase)

#endif /* MINIMUM_OS_VERSION */

/****************************************************************************/

/* Forward declarations for local routines. */
static LONG main(void);
static ULONG get_stack_size(void);
static void stack_usage_init(struct StackSwapStruct * stk);
static ULONG stack_usage_exit(const struct StackSwapStruct * stk);
static LONG CVSPrintf(const TEXT * format_string, APTR args);
static int LocalVSNPrintf(STRPTR buffer, int limit, const TEXT * formatString, APTR args);
static void cleanup(void);
static BOOL setup(const TEXT * program_name, const TEXT * service, const TEXT * workgroup, STRPTR username, STRPTR opt_password, BOOL opt_change_username_case, BOOL opt_change_password_case, const TEXT * opt_clientname, const TEXT * opt_servername, int opt_cachesize, int opt_max_transmit, int opt_timeout, LONG *opt_time_zone_offset, LONG *opt_dst_offset, BOOL opt_raw_smb, BOOL opt_unicode, BOOL opt_prefer_core_protocol, BOOL opt_session_setup_delay_unicode, BOOL opt_write_behind, int opt_smb_request_write_threshold, int opt_smb_request_read_threshold, BOOL scatter_gather, BOOL tcp_no_delay, int socket_receive_buffer_size, int socket_send_buffer_size, const TEXT * device_name, const TEXT * volume_name, BOOL add_volume, const TEXT * translation_file);
static void file_system_handler(BOOL raise_priority, const TEXT * device_name, const TEXT * volume_name, const TEXT * service_name);

/****************************************************************************/

struct Library * SysBase;
struct Library * DOSBase;
struct Library * UtilityBase;
struct Library * IntuitionBase;
struct Library * SocketBase;
struct Library * LocaleBase;
struct Library * TimerBase;
struct Library * IconBase;

/****************************************************************************/

#if defined(__amigaos4__)

/****************************************************************************/

struct ExecIFace *		IExec;
struct DOSIFace *		IDOS;
struct UtilityIFace *	IUtility;
struct IntuitionIFace *	IIntuition;
struct SocketIFace *	ISocket;
struct LocaleIFace *	ILocale;
struct TimerIFace *		ITimer;
struct IconIFace *		IIcon;

/****************************************************************************/

#endif /* __amigaos4__ */

/****************************************************************************/

struct timerequest * TimerRequest;
struct MsgPort * TimerPort;
BOOL TimerTicking;

/****************************************************************************/

struct Locale * Locale;

/****************************************************************************/

int errno;
int h_errno;

/****************************************************************************/

int profile_nest_count;

/****************************************************************************/

static struct DosList *		DeviceNode;
static BOOL					DeviceNodeAdded;
static struct DosList *		VolumeNode;
static BOOL					VolumeNodeAdded;
static struct MsgPort *		FileSystemPort;

static smba_server_t *		ServerData;

static const TEXT *			ErrorOutput;

static BOOL					Quit;
static BOOL					Quiet;
static BOOL					CaseSensitive;
static BOOL					OmitHidden;
static BOOL					DisableExAll;

static LONG					DSTOffset;
static LONG					TimeZoneOffset;
static BOOL					OverrideLocaleTimeZone;

static BOOL					WriteProtected;
static ULONG				WriteProtectKey;

static struct MinList		FileList;
static struct MinList		LockList;

#ifdef USE_SPLAY_TREE

static struct splay_tree	FileAddressTree;
static struct splay_tree	FileNameTree;

static struct splay_tree	LockAddressTree;
static struct splay_tree	LockNameTree;

#endif /* USE_SPLAY_TREE */

static APTR					MemoryPool;
static ULONG				total_memory_allocated;
static ULONG				max_memory_allocated;

static struct RDArgs *		Parameters;
static struct DiskObject *	Icon;

static struct WBStartup *	WBStartup;

static struct MinList		ErrorList;

static STRPTR				NewProgramName;

static BOOL					TranslateNames;

static TEXT					map_amiga_to_smb_name[256];
static TEXT					map_smb_to_amiga_name[256];

static LONG					MaxNameLen;

static BOOL					file_system_disabled;

/****************************************************************************/

/* This the default user name needed if no specific user name is provided.
 * Because the user name may have to be converted to all-upper-case characters
 * it must be writable (and not marked as "const").
 */
static TEXT guest_name[] = "GUEST";

/****************************************************************************/

#if defined(__amigaos4__)

/* The AmigaOS 2.x/3.x version needs about 20000 bytes of stack,
 * which is allocated at runtime. This is how it's done with
 * AmigaOS 4.x, for which the shell allocates the stack
 * before launching the program.
 */
const char stack_size_cookie[] = "$STACK: 30000";

#endif /* __amigaos4__ */

/****************************************************************************/

extern int STDARGS swap_stack_and_call(struct StackSwapStruct * stk,APTR function);

/****************************************************************************/

LONG SAVE_DS
_start(STRPTR args, LONG args_length, struct ExecBase * exec_base)
{
	struct StackSwapStruct * stk = NULL;
	APTR new_stack = NULL;
	LONG minimum_stack_size = 20000;
	LONG new_stack_size = 0;
	struct Process * this_process;
	LONG result = RETURN_FAIL;

	#if defined(__amigaos4__)
	{
		SysBase = (struct Library *)exec_base;

		IExec = (struct ExecIFace *)((struct ExecBase *)SysBase)->MainInterface;
	}
	#else
	{
		SysBase = (struct Library *)AbsExecBase;
	}
	#endif /* __amigaos4__ */

	/* Pick up the Workbench startup message, if
	 * there is one.
	 */
	this_process = (struct Process *)FindTask(NULL);
	if(this_process->pr_CLI == ZERO)
	{
		WaitPort(&this_process->pr_MsgPort);
		WBStartup = (struct WBStartup *)GetMsg(&this_process->pr_MsgPort);
	}
	else
	{
		WBStartup = NULL;
	}

	/* Open the libraries we need and check
	 * whether we could get them.
	 */
	DOSBase = OpenLibrary("dos.library",0);

	#if defined(__amigaos4__)
	{
		if(DOSBase != NULL)
		{
			IDOS = (struct DOSIFace *)GetInterface(DOSBase, "main", 1, 0);
			if(IDOS == NULL)
			{
				CloseLibrary(DOSBase);
				DOSBase = NULL;
			}
		}
	}
	#endif /* __amigaos4__ */

	UtilityBase = OpenLibrary("utility.library",37);

	#if defined(__amigaos4__)
	{
		if(UtilityBase != NULL)
		{
			IUtility = (struct UtilityIFace *)GetInterface(UtilityBase, "main", 1, 0);
			if(IUtility == NULL)
			{
				CloseLibrary(UtilityBase);
				UtilityBase = NULL;
			}
		}
	}
	#endif /* __amigaos4__ */

	if(UtilityBase == NULL || DOSBase == NULL || DOSBase->lib_Version < MINIMUM_OS_VERSION)
	{
		/* Complain loudly if this is not the operating
		 * system version we expected.
		 */
		if(DOSBase != NULL && this_process->pr_CLI != ZERO)
		{
			STRPTR msg;

			#if (MINIMUM_OS_VERSION < 39)
			{
				msg = "AmigaOS 2.04 or higher required.\n";
			}
			#else
			{
				msg = "AmigaOS 3.0 or higher required.\n";
			}
			#endif /* MINIMUM_OS_VERSION */

			Write(Output(),msg,strlen(msg));
		}

		goto out;
	}

	/* For AmigaOS4 we expect the stack size to be
	 * sufficient, because of the "STACK" string
	 * cookie.
	 */
	#if defined(__amigaos4__)
	{
		result = main();
	}
	/* For AmigaOS 2.x/3.x we check how much stack size the
	 * program has available and, if necessary, allocate
	 * a larger stack and use that instead.
	 */
	#else
	{
		#if defined(__SASC) && defined(_PROFILE) && _PROFILE
		{
			extern int __stdargs _STI_150_Sprof(void);

			_STI_150_Sprof();
		}
		#endif

		/* Not enough stack size available? */
		if(get_stack_size() < minimum_stack_size)
		{
			/* Make the new stack size a multiple of 32 bytes. */
			new_stack_size = 32 + ((minimum_stack_size + 31UL) & ~31UL);

			/* Allocate the new stack swapping data structure
			 * and the stack space separately.
			 */
			stk = AllocMem(sizeof(*stk),MEMF_PUBLIC|MEMF_ANY);
			if(stk == NULL)
				goto out;

			new_stack = AllocMem(new_stack_size,MEMF_ANY);
			if(new_stack == NULL)
				goto out;

			/* Fill in the lower and upper bounds, then take care of
			 * the stack pointer itself.
			 */
			stk->stk_Lower		= new_stack;
			stk->stk_Upper		= ((ULONG)new_stack) + new_stack_size;
			stk->stk_Pointer	= (APTR)(stk->stk_Upper - 32);

			/* Testing: fill the stack with a preset pattern, so that we
			 * can measure later how much stack space was used.
			 */
			/* stack_usage_init(stk); */

			result = swap_stack_and_call(stk,(APTR)main);

			/* Testing: figure out how much stack space was used. */
			/* Printf("stack size used = %lu\n",stack_usage_exit(stk)); */
		}
		/* Sufficient stack space should be available. */
		else
		{
			result = main();
		}

		#if defined(__SASC) && defined(_PROFILE) && _PROFILE
		{
			extern void __stdargs _STD_150_Sprof(void);

			_STD_150_Sprof();
		}
		#endif
	}
	#endif /* __amigaos4__ */

 out:

	if(stk != NULL)
		FreeMem(stk, sizeof(*stk));

	if(new_stack != NULL && new_stack_size > 0)
		FreeMem(new_stack,new_stack_size);

	#if defined(__amigaos4__)
	{
		if(IUtility != NULL)
		{
			DropInterface((struct Interface *)IUtility);
			IUtility = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(UtilityBase != NULL)
	{
		CloseLibrary(UtilityBase);
		UtilityBase = NULL;
	}

	#if defined(__amigaos4__)
	{
		if(IDOS != NULL)
		{
			DropInterface((struct Interface *)IDOS);
			IDOS = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(DOSBase != NULL)
	{
		CloseLibrary(DOSBase);
		DOSBase = NULL;
	}

	if(WBStartup != NULL)
	{
		Forbid();
		ReplyMsg((struct Message *)WBStartup);
	}

	return(result);
}

/****************************************************************************/

/* Figure out how much stack size is available to the running
 * Task. Returns the size in bytes.
 */
static ULONG
get_stack_size(void)
{
	struct Task * tc = FindTask(NULL);
	ULONG upper,lower;
	ULONG result;

	/* How much stack size was provided? */
	upper = (ULONG)tc->tc_SPUpper;
	lower = (ULONG)tc->tc_SPLower;

	result = upper - lower;

	return(result);
}

/****************************************************************************/

/* This byte value is used to detect how much stack size
 * was being used.
 */
#define STACK_FILL_COOKIE 0xA1

/****************************************************************************/

/* Testing: Fill the stack memory with a well-defined value which can later
 * be used to figure out how much stack space was used by the program.
 * This is needed by stack_usage_exit().
 */
static void
stack_usage_init(struct StackSwapStruct * stk)
{
	size_t stack_size = ((ULONG)stk->stk_Upper - (ULONG)stk->stk_Lower);

	memset(stk->stk_Lower,STACK_FILL_COOKIE,stack_size);
}

/* Testing: Check how much stack space was used by looking at where
 * the test pattern previously written to the stack memory was
 * overwritten. Returns how much space was used (in bytes).
 */
static ULONG
stack_usage_exit(const struct StackSwapStruct * stk)
{
	const UBYTE * m = (const UBYTE *)stk->stk_Lower;
	size_t stack_size = ((ULONG)stk->stk_Upper - (ULONG)stk->stk_Lower);
	size_t unused_stack_space,i;

	unused_stack_space = 0;

	/* Figure out how much of the stack was used by checking
	 * if the fill pattern was overwritten.
	 */
	for(i = 0 ; i < stack_size ; i++)
	{
		/* Strangely, the first long word is always trashed,
		 * even if the stack doesn't grow down this far...
		 */
		if(i > sizeof(LONG) && m[i] != STACK_FILL_COOKIE)
			break;

		unused_stack_space++;
	}

	return(stack_size - unused_stack_space);
}

/****************************************************************************/

/* Find out which switch keyword corresponds to TRUE or FALSE,
 * and fall back onto a default value if no keyword was provided,
 * or the keyword provided does not match what we have.
 */
static LONG
get_switch_status(const TEXT * value,LONG default_value)
{
	LONG result = default_value;

	if(value != NULL)
	{
		const struct { const TEXT * key; BOOL value; } options[] =
		{
			{ "yes",	TRUE },
			{ "true",	TRUE },
			{ "on",		TRUE },
			{ "no",		FALSE },
			{ "false",	FALSE },
			{ "off",	FALSE },
			{ NULL,		0 }
		};

		int i;

		for(i = 0 ; options[i].key != NULL ; i++)
		{
			if(Stricmp(value, options[i].key) == SAME)
			{
				result = options[i].value;
				break;
			}
		}
	}

	return(result);
}

/****************************************************************************/

/* Shortcut for retrieving the value of an icon tool type, even if it
 * has more than one name.
 */
static STRPTR
get_icon_tool_type_value(TEXT * name,TEXT * alternative_name)
{
	STRPTR value = NULL;

	if(Icon != NULL)
	{
		value = FindToolType(Icon->do_ToolTypes, name);
		if(value == NULL && alternative_name != NULL)
			value = FindToolType(Icon->do_ToolTypes, alternative_name);
	}

	return(value);
}

/****************************************************************************/

/* This is the traditional main() program. */
static LONG
main(void)
{
	struct
	{
		KEY		Workgroup;
		KEY		UserName;
		KEY		Password;
		KEY		ChangeUserNameCase;
		KEY		ChangePasswordCase;
		SWITCH	ChangeCase;
		SWITCH	CaseSensitive;
		SWITCH	OmitHidden;
		SWITCH	Quiet;
		SWITCH	RaisePriority;
		SWITCH	SetEnv;
		KEY		ClientName;
		KEY		ServerName;
		KEY		DeviceName;
		KEY		VolumeName;
		KEY		AddVolume;
		NUMBER	MaxNameLen;
		NUMBER	CacheSize;
		SWITCH	DisableExAll;
		NUMBER	MaxTransmit;
		NUMBER	Timeout;
		NUMBER	TimeZoneOffset;
		NUMBER	DSTOffset;
		KEY		ErrorOutput;
		KEY		Protocol;
		SWITCH	NetBIOSTransport;
		SWITCH	WriteBehind;
		NUMBER	WriteThreshold;
		NUMBER	ReadThreshold;
		KEY		ScatterGather;
		SWITCH	TCPNoDelay;
		KEY		TCPDelay;
		NUMBER	SocketReceiveBuf;
		NUMBER	SocketSendBuf;
		KEY		SessionSetup;
		KEY		Unicode;
		SWITCH	CP437;
		SWITCH	CP850;
		KEY		TranslationFile;
		KEY		Service;
		NUMBER	DebugLevel;
		KEY		DebugFile;
		SWITCH	DumpSMB;
		NUMBER	DumpSMBLevel;
		KEY		DumpSMBFile;
	} args;

	STRPTR cmd_template =
		"DOMAIN=WORKGROUP/K,"
		"USER=USERNAME/K,"
		"PASSWORD/K,"
		"CHANGEUSERNAMECASE/K,"
		"CHANGEPASSWORDCASE/K,"
		"CHANGECASE/S,"
		"CASE=CASESENSITIVE/S,"
		"OMITHIDDEN/S,"
		"QUIET/S,"
		"RAISEPRIORITY/S,"
		"SETENV/S,"
		"CLIENT=CLIENTNAME/K,"
		"SERVER=SERVERNAME/K,"
		"DEVICE=DEVICENAME/K,"
		"VOLUME=VOLUMENAME/K,"
		"ADDVOLUME/K,"
		"MAXNAMELEN/N/K,"
		"CACHE=CACHESIZE/N/K,"
		"DISABLEEXALL/S,"
		"MAXTRANSMIT/N/K,"
		"TIMEOUT/N/K,"
		"TZ=TIMEZONEOFFSET/N/K,"
		"DST=DSTOFFSET/N/K,"
		"ERROROUTPUT/K,"
		"PROTOCOL/K,"
		"NETBIOS/S,"
		"WRITEBEHIND/S,"
		"WRITETHRESHOLD/N/K,"
		"READTHRESHOLD/N/K,"
		"SCATTERGATHER/K,"
		"TCP_NODELAY=TCPNODELAY/S,"
		"TCPDELAY/K,"
		"SO_RCVBUF=SOCKETRECEIVEBUFFER/N/K,"
		"SO_SNDBUF=SOCKETSENDBUFFER/N/K,"
		"SESSIONSETUP/K,"
		"UNICODE/K,"
		"CP437/S,"
		"CP850/S,"
		"TRANSLATE=TRANSLATIONFILE/K,"
		"SHARE=SERVICE/A,"
		"DEBUGLEVEL=DEBUG/N/K,"
		"DEBUGFILE/K,"
		"DUMPSMB/S,"
		"DUMPSMBLEVEL/N/K,"
		"DUMPSMBFILE/K";

	BPTR debug_file = ZERO;
	BOOL close_debug_file = FALSE;
	TEXT program_name[MAX_FILENAME_LEN+1];
	LONG result = RETURN_FAIL;
	LONG tz_number, dst_number, debug_number;
	LONG cache_size = 0;
	LONG max_transmit = -1;
	LONG smb_write_threshold = 0;
	LONG smb_read_threshold = 0;
	LONG timeout = 0;
	LONG socket_receive_buffer = 0;
	LONG socket_send_buffer = 0;
	TEXT env_protocol[8];
	TEXT env_workgroup_name[17];
	TEXT env_user_name[64];
	TEXT env_password[64];

	/* Don't emit any debugging output before we are ready. */
	SETDEBUGLEVEL(0);

	/* This needs to be set up properly for report_error()
	 * to work. The cleanup() function will eventually
	 * call it.
	 */
	NewList((struct List *)&ErrorList);

	/* The command parameters will be filled in either from
	 * icon tool types or from the CLI command line arguments.
	 */
	memset(&args,0,sizeof(args));

	/* If this program was launched from Workbench, the
	 * command parameters will have to be read from the
	 * icon tool types.
	 */
	if(WBStartup != NULL)
	{
		TEXT * icon_file_name;
		BPTR icon_file_lock;
		STRPTR str;
		BPTR old_dir;
		int size;
		int n;

		/* Get the name of the program, as it was launched
		 * from Workbench. We actually prefer the name of
		 * the first project file, if there is one.
		 */
		if(WBStartup->sm_NumArgs > 1)
			n = 1;
		else
			n = 0;

		icon_file_name = WBStartup->sm_ArgList[n].wa_Name;
		icon_file_lock = WBStartup->sm_ArgList[n].wa_Lock;

		strlcpy(program_name,FilePart(icon_file_name),sizeof(program_name));

		SETPROGRAMNAME(program_name);

		/* Now open icon.library and read that icon. */
		IconBase = OpenLibrary("icon.library",0);

		#if defined(__amigaos4__)
		{
			if(IconBase != NULL)
			{
				IIcon = (struct IconIFace *)GetInterface(IconBase, "main", 1, 0);
				if(IIcon == NULL)
				{
					CloseLibrary(IconBase);
					IconBase = NULL;
				}
			}
		}
		#endif /* __amigaos4__ */

		if(IconBase == NULL)
		{
			report_error("Could not open 'icon.library'.");
			goto out;
		}

		old_dir = CurrentDir(icon_file_lock);
		Icon = GetDiskObject(icon_file_name);
		CurrentDir(old_dir);

		if(Icon == NULL)
		{
			report_error("Icon file for '%s' not found.", icon_file_name);
			goto out;
		}

		/* Only input validation errors are reported below. */
		result = RETURN_ERROR;

		/* Get the debug options ready before we will deal
		 * with the remaining parameters.
		 */
		#if DEBUG
		{
			str = get_icon_tool_type_value("DEBUG","DEBUGLEVEL");
			if(str != NULL)
			{
				if(StrToLong(str,&debug_number) == -1 || debug_number < 0)
				{
					report_error("Invalid number '%s' for 'DEBUG' parameter.",str);
					goto out;
				}

				args.DebugLevel = &debug_number;
			}

			/* Configure the debugging options. */
			if(args.DebugLevel != NULL)
				SETDEBUGLEVEL(*args.DebugLevel);
			else
				SETDEBUGLEVEL(0);

			args.DebugFile = get_icon_tool_type_value("DEBUGFILE",NULL);
			if(args.DebugFile != NULL)
			{
				/* Try to append the output to an existing file
				 * or create a new file instead.
				 */
				debug_file = Open(args.DebugFile,MODE_READWRITE);
				if(debug_file != ZERO)
				{
					D_S(struct FileInfoBlock, fib);

					SetVBuf(debug_file, NULL, BUF_LINE, 512);

					Seek(debug_file,0,OFFSET_END);

					close_debug_file = TRUE;

					/* If the debug file is not empty, add a few
					 * line feeds to it, so that any new output
					 * will be separated from the old contents.
					 */
					if(ExamineFH(debug_file, fib) && fib->fib_Size > 0)
						FPrintf(debug_file,"\n\n");

					SETDEBUGFILE(debug_file);

					D(("%s (%s)", VERS, DATE));
				}
			}
		}
		#else
		{
			if(get_icon_tool_type_value("DEBUG","DEBUGLEVEL") != NULL || get_icon_tool_type_value("DEBUGFILE",NULL) != NULL)
			{
				report_error("This version of the smbfs program has no built-in debug support.");
				goto out;
			}
		}
		#endif /* DEBUG */

		/* Examine the icon's tool types and use the
		 * information to fill the startup parameter
		 * data structure.
		 */
		args.Service = get_icon_tool_type_value("SERVICE", "SHARE");
		if(args.Service == NULL)
		{
			report_error("'SERVICE' parameter needs an argument.");
			goto out;
		}

		/* Set up the name of the program, as it will be
		 * displayed in error requesters.
		 */
		size = strlen(icon_file_name) + strlen(" ''") + strlen(args.Service)+1;

		NewProgramName = AllocVec(size,MEMF_ANY|MEMF_PUBLIC);
		if(NewProgramName != NULL)
			LocalSNPrintf(NewProgramName,size,"%s '%s'",icon_file_name,args.Service);

		args.Workgroup = get_icon_tool_type_value("DOMAIN","WORKGROUP");
		args.UserName = get_icon_tool_type_value("USER","USERNAME");

		str = get_icon_tool_type_value("CHANGEUSERNAMECASE", NULL);
		args.ChangeUserNameCase = (str != NULL) ? str : (STRPTR)"yes";

		args.Password = get_icon_tool_type_value("PASSWORD", NULL);

		args.ChangePasswordCase = get_icon_tool_type_value("CHANGEPASSWORDCASE", NULL);
		if(args.ChangePasswordCase == NULL && get_icon_tool_type_value("CHANGECASE", NULL) != NULL)
			args.ChangePasswordCase = "yes";

		args.TCPDelay = get_icon_tool_type_value("TCPDELAY", NULL);
		if(args.TCPDelay == NULL && get_icon_tool_type_value("TCPNODELAY", "TCP_NODELAY") != NULL)
			args.TCPDelay = "no";

		args.DisableExAll = get_icon_tool_type_value("DISABLEEXALL", NULL) != NULL;
		args.OmitHidden = get_icon_tool_type_value("OMITHIDDEN", NULL) != NULL;
		args.Quiet = get_icon_tool_type_value("QUIET", NULL) != NULL;
		args.RaisePriority = get_icon_tool_type_value("RAISEPRIORITY", NULL) != NULL;
		args.CaseSensitive = get_icon_tool_type_value("CASE", "CASESENSITIVE") != NULL;
		args.NetBIOSTransport = get_icon_tool_type_value("NETBIOS", NULL) != NULL;
		args.WriteBehind = get_icon_tool_type_value("WRITEBEHIND", NULL) != NULL;

		args.ClientName = get_icon_tool_type_value("CLIENT", "CLIENTNAME");
		args.ServerName = get_icon_tool_type_value("SERVER", "SERVERNAME");
		args.DeviceName = get_icon_tool_type_value("DEVICE", "DEVICENAME");
		args.VolumeName = get_icon_tool_type_value("VOLUME", "VOLUMENAME");

		if(args.VolumeName == NULL)
			args.AddVolume = get_icon_tool_type_value("ADDVOLUME", NULL);

		str = get_icon_tool_type_value("MAXNAMELEN", NULL);
		if(str != NULL)
		{
			if(StrToLong(str,&MaxNameLen) == -1)
			{
				report_error("Invalid number '%s' for 'MAXNAMELEN' parameter.",str);
				goto out;
			}

			args.MaxNameLen = &MaxNameLen;
		}

		str = get_icon_tool_type_value("WRITETHRESHOLD", NULL);
		if(str != NULL)
		{
			if(StrToLong(str,&smb_write_threshold) == -1)
			{
				report_error("Invalid number '%s' for 'WRITETHRESHOLD' parameter.",str);
				goto out;
			}

			args.WriteThreshold = &smb_write_threshold;
		}

		str = get_icon_tool_type_value("READTHRESHOLD", NULL);
		if(str != NULL)
		{
			if(StrToLong(str,&smb_read_threshold) == -1)
			{
				report_error("Invalid number '%s' for 'READTHRESHOLD' parameter.",str);
				goto out;
			}

			args.ReadThreshold = &smb_read_threshold;
		}

		args.ScatterGather = get_icon_tool_type_value("SCATTERGATHER", NULL);

		str = get_icon_tool_type_value("TZ","TIMEZONEOFFSET");
		if(str != NULL)
		{
			if(StrToLong(str,&tz_number) == -1)
			{
				report_error("Invalid number '%s' for 'TIMEZONEOFFSET' parameter.",str);
				goto out;
			}

			args.TimeZoneOffset = &tz_number;
		}

		str = get_icon_tool_type_value("DST", "DSTOFFSET");
		if(str != NULL)
		{
			if(StrToLong(str,&dst_number) == -1)
			{
				report_error("Invalid number '%s' for 'DSTOFFSET' parameter.",str);
				goto out;
			}

			args.DSTOffset = &dst_number;
		}

		args.Protocol = get_icon_tool_type_value("PROTOCOL", NULL);
		args.SessionSetup = get_icon_tool_type_value("SESSIONSETUP", NULL);

		args.TranslationFile = get_icon_tool_type_value("TRANSLATE", "TRANSLATIONFILE");
		args.Unicode = get_icon_tool_type_value("UNICODE", NULL);
		args.CP437 = get_icon_tool_type_value("CP437", NULL) != NULL;
		args.CP850 = get_icon_tool_type_value("CP850", NULL) != NULL;

		str = get_icon_tool_type_value("CACHE","CACHESIZE");
		if(str != NULL)
		{
			if(StrToLong(str,&cache_size) == -1)
			{
				report_error("Invalid number '%s' for 'CACHE' parameter.",str);
				goto out;
			}

			args.CacheSize = &cache_size;
		}

		str = get_icon_tool_type_value("MAXTRANSMIT", NULL);
		if(str != NULL)
		{
			if(StrToLong(str,&max_transmit) == -1)
			{
				report_error("Invalid number '%s' for 'MAXTRANSMIT' parameter.",str);
				goto out;
			}

			args.MaxTransmit = &max_transmit;
		}

		str = get_icon_tool_type_value("TIMEOUT", NULL);
		if(str != NULL)
		{
			if(StrToLong(str,&timeout) == -1)
			{
				report_error("Invalid number '%s' for 'TIMEOUT' parameter.",str);
				goto out;
			}

			args.Timeout = &timeout;
		}

		str = get_icon_tool_type_value("SOCKETRECEIVEBUFFER", "SO_RCVBUF");
		if(str != NULL)
		{
			if(StrToLong(str,&socket_receive_buffer) == -1)
			{
				report_error("Invalid number '%s' for 'SOCKETRECEIVEBUFFER' parameter.",str);
				goto out;
			}

			args.SocketReceiveBuf = &socket_receive_buffer;
		}

		str = get_icon_tool_type_value("SOCKETSENDBUFFER", "SO_SENDBUF");
		if(str != NULL)
		{
			if(StrToLong(str,&socket_send_buffer) == -1)
			{
				report_error("Invalid number '%s' for 'SOCKETSENDBUFFER' parameter.",str);
				goto out;
			}

			args.SocketSendBuf = &socket_send_buffer;
		}
	}
	else
	{
		const TEXT * name;
		int size;

		/* Only input validation errors are reported below. */
		result = RETURN_ERROR;

		GetProgramName(program_name,sizeof(program_name));

		SETPROGRAMNAME(FilePart(program_name));

		Parameters = ReadArgs(cmd_template,(LONG *)&args,NULL);
		if(Parameters == NULL)
		{
			PrintFault(IoErr(),FilePart(program_name));
			goto out;
		}

		#if DEBUG
		{
			/* Configure the debugging options. */
			if(args.DebugLevel != NULL)
				SETDEBUGLEVEL(*args.DebugLevel);
			else
				SETDEBUGLEVEL(0);

			if(args.DebugFile != NULL)
			{
				/* Try to append the output to an existing file
				 * or create a new file instead.
				 */
				debug_file = Open(args.DebugFile,MODE_READWRITE);
				if(debug_file != ZERO)
				{
					D_S(struct FileInfoBlock, fib);

					SetVBuf(debug_file, NULL, BUF_LINE, 512);

					Seek(debug_file,0,OFFSET_END);

					close_debug_file = TRUE;

					/* If the debug file is not empty, add a few
					 * line feeds to it, so that any new output
					 * will be separated from the old contents.
					 */
					if(ExamineFH(debug_file, fib) && fib->fib_Size > 0)
						FPrintf(debug_file,"\n\n");
				}
			}
			else
			{
				debug_file = Output();
			}

			SETDEBUGFILE(debug_file);
		}
		#else
		{
			if(args.DebugLevel != NULL || args.DebugFile != NULL)
			{
				report_error("This version of the smbfs program has no built-in debug support.");
				goto out;
			}
		}
		#endif /* DEBUG */

		D(("%s (%s)", VERS, DATE));

		ASSERT( args.Service != NULL );

		/* Set up the name of the program, as it will be
		 * displayed in the proces status list.
		 */
		name = FilePart(program_name);

		size = strlen(name) + strlen(" ''") + strlen(args.Service)+1;

		NewProgramName = AllocVec(size,MEMF_ANY|MEMF_PUBLIC);
		if(NewProgramName != NULL)
			LocalSNPrintf(NewProgramName,size,"%s '%s'",name,args.Service);
	}

	/* If no workgroup/domain was given, try the environment variables. */
	if(args.Workgroup == NULL)
	{
		static const char * names[] =
		{
			"smbfs_domain",
			"smbfs_workgroup",
			NULL
		};

		int i;

		for(i = 0 ; names[i] != NULL ; i++)
		{
			if(GetVar(names[i],env_workgroup_name,sizeof(env_workgroup_name),0) > 0)
			{
				D(("using WORKGROUP='%s' stored in '%s' environment variable.", env_workgroup_name, names[i]));

				args.Workgroup = env_workgroup_name;
				break;
			}
		}
	}

	/* If no user name was given, try the environment variables. */
	if(args.UserName == NULL)
	{
		static const char * names[] =
		{
			"smbfs_user",
			"smbfs_username",
			NULL
		};

		int i;

		for(i = 0 ; names[i] != NULL ; i++)
		{
			if(GetVar(names[i],env_user_name,sizeof(env_user_name),0) > 0)
			{
				D(("using USER='%s' stored in '%s' environment variable.", env_user_name, names[i]));

				args.UserName = env_user_name;
				break;
			}
		}
	}

	/* If no password was given, try the environment variable. */
	if(args.Password == NULL)
	{
		if(GetVar("smbfs_password",env_password,sizeof(env_password),0) > 0)
		{
			SHOWMSG("using PASSWORD=... stored in 'smbfs_password' environment variable.");

			args.Password = env_password;
		}
	}

	/* If no protocol was given, try the environment variable. */
	if(args.Protocol == NULL)
	{
		if(GetVar("smbfs_protocol",env_protocol,sizeof(env_protocol),0) > 0)
		{
			D(("using PROTOCOL='%s' stored in 'smbfs_protocol' environment variable.", env_protocol));

			args.Protocol = env_protocol;
		}
	}

	/* Use the default if no user name is given. */
	if(args.UserName == NULL)
	{
		args.UserName = guest_name;

		D(("no user name given, using '%s' instead.", args.UserName));
	}

	/* Change the case of the user name? */
	if(args.ChangeUserNameCase == NULL)
		args.ChangeUserNameCase = "yes";

	/* Change the case of the password? */
	if(args.ChangePasswordCase == NULL && args.ChangeCase)
		args.ChangePasswordCase = "yes";

	/* Disable the TCP delay? */
	if(args.TCPDelay == NULL && args.TCPNoDelay)
		args.TCPDelay = "no";

	/* Use the default if no device or volume name is given. */
	if(args.DeviceName == NULL && args.VolumeName == NULL)
	{
		args.DeviceName = "SMBFS";

		D(("no device/volume name given, using 'devicename=%s' instead.", args.DeviceName));
	}

	if(args.VolumeName != NULL)
		args.AddVolume = "yes";

	/* Where do we send error messages to if started from shell? */
	if(WBStartup == NULL)
	{
		if(args.Protocol != NULL && Stricmp(args.Protocol,"stderr") == SAME)
			args.Protocol = NULL;

		if(args.Protocol != NULL && Stricmp(args.Protocol,"stdout") != SAME)
		{
			report_error("'ERROROUTPUT' parameter must be either 'STDERR' or 'STDOUT'.");
			goto out;
		}

		D(("using 'erroroutput=%s'.", (args.ErrorOutput != NULL) ? "stderr" : "stdout"));

		ErrorOutput = args.ErrorOutput;
	}

	/* Restrict the command set which smbfs uses? */
	if(args.Protocol == NULL)
	{
		args.Protocol = "CORE";

		D(("using 'protocol=%s'.", args.Protocol));
	}

	if(Stricmp(args.Protocol,"NT1") != SAME && Stricmp(args.Protocol,"CORE") != SAME)
	{
		report_error("'PROTOCOL' parameter must be either 'NT1' or 'CORE'.");
		goto out;
	}

	if(args.SessionSetup == NULL)
	{
		args.SessionSetup = "DELAY";

		D(("using 'sessionsetup=%s'.", args.SessionSetup));
	}

	if(Stricmp(args.SessionSetup,"DELAY") != SAME && Stricmp(args.SessionSetup,"NODELAY") != SAME)
	{
		report_error("'SESSIONSETUP' parameter must be either 'DELAY' or 'NODELAY'.");
		goto out;
	}

	/* Disable Unicode support for path names, etc.? */
	if(args.Unicode == NULL)
	{
		args.Unicode = "ON";

		D(("using 'unicode=%s'.", args.Unicode));
	}

	/* Is the Unicode parameter even valid? */
	if(get_switch_status(args.Unicode,-1) == -1)
	{
		report_error("'UNICODE' parameter must be either 'ON' or 'OFF'.");
		goto out;
	}

	/* Code page based translation using a file disables
	 * Unicode support and the built-in CP437 and CP850
	 * translation.
	 */
	if (args.TranslationFile != NULL)
	{
		args.CP437 = args.CP850 = FALSE;
		args.Unicode = "off";
	}
	/* Unicode support disables the code-page based
	 * translation.
	 */
	else if (get_switch_status(args.Unicode, FALSE))
	{
		args.CP437 = args.CP850 = FALSE;
	}
	else
	{
		if(args.CP437 && args.CP850)
		{
			report_error("You can use either the 'CP437' or the 'CP850' parameters, but not both.");
			goto out;
		}
	}

	/* Use one of the built-in code page translation tables? */
	if (args.CP437)
	{
		SHOWMSG("using code page 437 translation");

		memcpy(map_amiga_to_smb_name,unicode_to_cp437,sizeof(unicode_to_cp437));
		memcpy(map_smb_to_amiga_name,cp437_to_unicode,sizeof(cp437_to_unicode));

		TranslateNames = TRUE;
	}
	else if (args.CP850)
	{
		SHOWMSG("using code page 850 translation");

		memcpy(map_amiga_to_smb_name,unicode_to_cp850,sizeof(unicode_to_cp850));
		memcpy(map_smb_to_amiga_name,cp850_to_unicode,sizeof(cp850_to_unicode));

		TranslateNames = TRUE;
	}

	if(args.MaxNameLen != NULL)
	{
		MaxNameLen = (*args.MaxNameLen);
		if(MaxNameLen <= 0)
		{
			report_error("'MAXNAMELEN' parameter must be > 0.");
			goto out;
		}
	}

	if(args.CacheSize != NULL)
	{
		cache_size = (*args.CacheSize);
		if(cache_size <= 0)
		{
			report_error("'CACHESIZE' parameter must be > 0.");
			goto out;
		}
	}

	if(args.MaxTransmit != NULL)
	{
		max_transmit = (*args.MaxTransmit);
		if(max_transmit <= 0)
		{
			report_error("'MAXTRANSMIT' parameter must be > 0.");
			goto out;
		}
	}

	if(args.Timeout != NULL)
	{
		timeout = (*args.Timeout);
		if(timeout <= 0)
		{
			report_error("'TIMEOUT' parameter must be > 0.");
			goto out;
		}
	}

	if(args.WriteThreshold == NULL)
		args.WriteThreshold = &smb_write_threshold;

	D(("write threshold = %ld", (*args.WriteThreshold)));

	if(args.ReadThreshold == NULL)
		args.ReadThreshold = &smb_read_threshold;

	D(("read threshold = %ld", (*args.ReadThreshold)));

	D(("scatter gather = %s", get_switch_status(args.ScatterGather, FALSE) ? "enabled" : "disabled"));

	D(("tcp delay = %s", get_switch_status(args.TCPDelay, FALSE) ? "enabled" : "disabled"));

	if(args.SocketReceiveBuf == NULL)
		args.SocketReceiveBuf = &socket_receive_buffer;

	D(("socket receive buffer size = %ld", (*args.SocketReceiveBuf)));

	if(args.SocketSendBuf == NULL)
		args.SocketSendBuf = &socket_send_buffer;

	D(("socket send buffer size = %ld", (*args.SocketSendBuf)));

	DisableExAll = (BOOL)(args.DisableExAll != 0);
	CaseSensitive = (BOOL)(args.CaseSensitive != 0);
	OmitHidden = (BOOL)(args.OmitHidden != 0);

	D(("disable exall = %s", DisableExAll ? "yes": "no"));
	D(("case sensitive = %s", CaseSensitive ? "yes": "no"));
	D(("omit hidden = %s", OmitHidden ? "yes": "no"));

	/* Enable SMB packet decoding, but only if not started from Workbench. */
	#if defined(DUMP_SMB)
	{
		LONG dump_smb_level = 0;

		if(args.DumpSMBLevel != NULL)
			dump_smb_level = (*args.DumpSMBLevel);

		if(args.DumpSMB && WBStartup == NULL)
			control_smb_dump(TRUE, dump_smb_level, (const char *)args.DumpSMBFile);
	}
	#else
	{
		if(WBStartup == NULL && (args.DumpSMBLevel != NULL || args.DumpSMB))
			report_error("This version of smbfs cannot create SMB debug output.");
	}
	#endif /* DUMP_SMB */

	D(("service = '%s'.", args.Service));
	D(("work group = '%s'.", args.Workgroup));
	D(("user name = '%s'.", args.UserName));

	D(("change user name case = %s", get_switch_status(args.ChangeUserNameCase, TRUE) ? "yes" : "no"));

	if(args.Password != NULL)
		SHOWMSG("password = ...");
	else
		SHOWMSG("password = empty");

	D(("change password case = %s", get_switch_status(args.ChangePasswordCase, FALSE) ? "yes" : "no"));
	D(("unicode = '%s'", args.Unicode));
	D(("protocol = '%s'", args.Protocol));
	D(("netbios transport = '%s'", args.NetBIOSTransport ? "yes" : "no"));
	D(("session setup = '%s'", args.SessionSetup));

	if(args.ClientName != NULL)
		D(("client name = '%s'.", args.ClientName));
	else
		D(("client name = NULL."));

	if(args.ServerName != NULL)
		D(("server name = '%s'.", args.ServerName));
	else
		D(("server name = NULL."));

	if(args.TimeZoneOffset != NULL)
		D(("time zone offset = %ld.", (*args.TimeZoneOffset)));
	else
		D(("time zone offset = NULL"));

	if(args.DSTOffset != NULL)
		D(("dst offset = %ld.", (*args.DSTOffset)));
	else
		D(("dst offset = NULL"));

	D(("write behind = %s", args.WriteBehind ? "yes" : "no"));

	if(args.DeviceName != NULL)
		D(("device name = '%s'.", args.DeviceName));
	else
		D(("device name = NULL."));

	if(args.VolumeName != NULL)
		D(("volume name = '%s'.", args.VolumeName));
	else
		D(("volume name = NULL."));

	D(("add volume = %s", args.AddVolume));

	if(args.TranslationFile != NULL)
		D(("translation file = '%s'.", args.TranslationFile));
	else
		D(("translation file = NULL."));

	D(("use cp437 = %s.", args.CP437 ? "yes" : "no"));

	D(("use cp850 = %s.", args.CP850 ? "yes" : "no"));

	D(("max name length = %ld.", MaxNameLen));
	D(("cache size = %ld.", cache_size));
	D(("max transmit = %ld.", max_transmit));
	D(("timeout = %ld.", timeout));

	if(setup(
		FilePart(program_name),
		args.Service,
		args.Workgroup,
		args.UserName,
		args.Password,
		get_switch_status(args.ChangeUserNameCase, TRUE),
		get_switch_status(args.ChangePasswordCase, FALSE),
		args.ClientName,
		args.ServerName,
		cache_size,
		max_transmit,
		timeout,
		args.TimeZoneOffset,
		args.DSTOffset,
		!args.NetBIOSTransport,	/* Use raw SMB transport instead of NetBIOS transport? */
		Stricmp(args.Unicode,"OFF") != SAME,
		Stricmp(args.Protocol,"CORE") == SAME,
		Stricmp(args.SessionSetup,"DELAY") == SAME,
		args.WriteBehind,
		(*args.WriteThreshold),
		(*args.ReadThreshold),
		get_switch_status(args.ScatterGather, FALSE),
		get_switch_status(args.TCPDelay, FALSE),
		(*args.SocketReceiveBuf),
		(*args.SocketSendBuf),
		args.DeviceName,
		args.VolumeName,
		get_switch_status(args.AddVolume, TRUE),
		args.TranslationFile))
	{
		char setenv_name[40];

		Quiet = args.Quiet;

		if(Locale != NULL)
			SHOWVALUE(Locale->loc_GMTOffset);

		/* This is where the CLI process number identifying
		 * this smbfs instance goes.
		 */
		memset(setenv_name,0,sizeof(setenv_name));

		/* Store the CLI process number of this smbfs
		 * instance in an environment variable?
		 */
		if(Cli() != NULL && args.SetEnv)
		{
			const struct Process * this_process = (struct Process *)FindTask(NULL);
			LONG which_cli = -1;
			LONG max_cli;
			LONG i;

			/* Which CLI process number does this process use? */
			Forbid();

			max_cli = MaxCli();

			for(i = 1 ; i <= max_cli ; i++)
			{
				if(FindCliProc(i) == this_process)
				{
					which_cli = i;
					break;
				}
			}

			Permit();

			if(which_cli > 0)
			{
				char number[20];
				int i, len;

				LocalSNPrintf(number, sizeof(number),"%ld\n",which_cli);

				LocalSNPrintf(setenv_name, sizeof(setenv_name),"smbfs-process/%b",DeviceNode->dol_Name);

				for(i = 0, len = strlen(setenv_name) ; i < len ; i++)
					setenv_name[i] = ToLower(setenv_name[i]);

				SetVar(setenv_name,number,-1,GVF_GLOBAL_ONLY);
			}
		}

		file_system_handler(args.RaisePriority,args.DeviceName,args.VolumeName,args.Service);

		/* Clean up after the environment variable... */
		if(setenv_name[0] != '\0')
			DeleteVar(setenv_name,GVF_GLOBAL_ONLY);

		result = RETURN_WARN;
	}
	else
	{
		result = RETURN_ERROR;
	}

 out:

	#if DEBUG
	{
		D(("total amount of memory allocated = %lu", total_memory_allocated));
		D(("maximum amount of memory allocated = %lu", max_memory_allocated));
	}
	#endif /* DEBUG */

	#if defined(DUMP_SMB)
	{
		if(args.DumpSMB && WBStartup == NULL)
			control_smb_dump(FALSE, 0, NULL);
	}
	#endif /* DUMP_SMB */

	cleanup();

	if(close_debug_file && debug_file != ZERO)
	{
		SETDEBUGFILE(ZERO);

		SETDEBUGLEVEL(0);

		Close(debug_file);
	}

	return(result);
}

/****************************************************************************/

/* Our own FPrintf(), which is needed because this code has to build
 * both for AmigaOS 2.x/3.x and 4.x, and with Lattice/SAS/GCC and the
 * header files make it difficult to do this. The FPrintf() declaration
 * is not always usable, depending upon which AmigaOS header file set
 * you are using.
 */
static LONG VARARGS68K
LocalFPrintf(BPTR output, const TEXT * format, ...)
{
	va_list args;
	LONG result;

	if(output == ZERO)
		output = Output();

	#if defined(__amigaos4__)
	{
		va_startlinear(args,format);
		result = VFPrintf(output, format, va_getlinearva(args,APTR));
		va_end(args);
	}
	#else
	{
		va_start(args,format);
		result = VFPrintf(output, format, args);
		va_end(args);
	}
	#endif /* __amigaos4__ */

	return(result);
}

/****************************************************************************/

/* Obtain the descriptive text corresponding to an error number
 * that may have been generated by the TCP/IP stack, or by
 * the SMB POSIX error conversion code.
 */
STRPTR
posix_strerror(int error)
{
	STRPTR result;

	/* Is this one of our own error codes? */
	if(error >= error_end_of_file)
	{
		static const struct { int code; const char * message; } messages[] =
		{
			{ error_end_of_file,					"end of file" },
			{ error_invalid_netbios_session,		"invalid NetBIOS session" },
			{ error_message_exceeds_buffer_size,	"message exceeds buffer size" },
			{ error_invalid_buffer_format,			"invalid buffer format" },
			{ error_data_exceeds_buffer_size,		"data exceeds buffer size" },
			{ error_invalid_parameter_size,			"invalid parameter size" },
			{ error_check_smb_error,				"check SMB error class and code" },
			{ error_server_setup_incomplete,		"server setup incomplete" },
			{ error_server_connection_invalid,		"server connection invalid" },
			{ error_smb_message_signature_missing,	"SMB message signature missing" },
			{ error_smb_message_too_short,			"SMB message too short" },
			{ error_smb_message_invalid_command,	"SMB message invalid command" },
			{ error_smb_message_invalid_word_count,	"SMB message invalid word count" },
			{ error_smb_message_invalid_byte_count,	"SMB message invalid byte count" },
			{ error_looping_in_find_next,			"looping in find_next" },
			{ error_invalid_directory_size,			"invalid directory size" },
			{ error_session_request_failed,			"session request failed" },
			{ error_unsupported_dialect,			"unsupported dialect" },
			{ -1, NULL }
		};

		int i;

		result = "";

		for(i = 0 ; messages[i].code != -1 ; i++)
		{
			if(messages[i].code == error)
			{
				result = (STRPTR)messages[i].message;
				break;
			}
		}
	}
	else
	{
		struct TagItem tags[2];

		tags[0].ti_Tag	= SBTM_GETVAL(SBTC_ERRNOSTRPTR);
		tags[0].ti_Data	= error;
		tags[1].ti_Tag	= TAG_END;

		PROFILE_OFF();

		SocketBaseTagList(tags);

		PROFILE_ON();

		result = (STRPTR)tags[0].ti_Data;
	}

	return(result);
}

/****************************************************************************/

/* Return the descriptive text associated with a host lookup failure code. */
STRPTR
host_strerror(int error)
{
	struct TagItem tags[2];
	STRPTR result;

	tags[0].ti_Tag	= SBTM_GETVAL(SBTC_HERRNOSTRPTR);
	tags[0].ti_Data	= error;
	tags[1].ti_Tag	= TAG_END;

	PROFILE_OFF();

	SocketBaseTagList(tags);

	PROFILE_ON();

	result = (STRPTR)tags[0].ti_Data;

	return(result);
}

/****************************************************************************/

/* Compare two strings, either case sensitive or not
 * sensitive to the case of the letters. How this is
 * to be done is controlled by a global option. This
 * routine is called whenever two SMB file names are
 * to be compared.
 */
LONG
compare_names(const TEXT * a,const TEXT * b)
{
	LONG result;

	if(CaseSensitive)
		result = strcmp(a,b);
	else
		result = Stricmp(a,b);

	return(result);
}

/****************************************************************************/

/* Translate a string into all upper case characters. */
void
string_toupper(STRPTR s)
{
	TEXT c;

	while((c = (*s)) != '\0')
		(*s++) = ToUpper(c);
}

/****************************************************************************/

/* Prepare the accumulated list of error messages for display
 * and purge the contents of that list.
 *
 * Unless the program was started from Workbench this function
 * will do nothing.
 */
static void
display_error_message_list(void)
{
	if(WBStartup != NULL)
	{
		struct MinNode * last = NULL;
		struct MinNode * mn;
		TEXT * message = NULL;
		const TEXT * str;
		int size;

		/* Determine how much memory will have to be
		 * allocated to hold all the accumulated
		 * error messages.
		 */
		size = 0;

		for(mn = ErrorList.mlh_Head ;
		    mn->mln_Succ != NULL ;
		    mn = mn->mln_Succ)
		{
			last = mn;

			str = (TEXT *)(mn + 1);

			size += strlen(str)+1;
		}

		/* Allocate the memory for the messages, then
		 * copy them there.
		 */
		if(size > 0)
		{
			message = AllocVec(size,MEMF_ANY);
			if(message != NULL)
			{
				int message_len;
				int len;

				message_len = 0;

				for(mn = ErrorList.mlh_Head ;
				    mn->mln_Succ != NULL ;
				    mn = mn->mln_Succ)
				{
					str = (TEXT *)(mn + 1);
					len = strlen(str);

					memcpy(&message[message_len], str, len);
					message_len += len;

					if(mn != last)
						message[message_len++] = '\n';
				}

				ASSERT( message_len < size );

				message[message_len] = '\0';
			}
		}

		/* Purge the list. */
		while((mn = (struct MinNode *)RemHead((struct List *)&ErrorList)) != NULL)
			FreeVec(mn);

		/* Display the error messages. */
		if(message != NULL)
		{
			IntuitionBase = OpenLibrary("intuition.library",37);

			#if defined(__amigaos4__)
			{
				if(IntuitionBase != NULL)
				{
					IIntuition = (struct IntuitionIFace *)GetInterface(IntuitionBase, "main", 1, 0);
					if(IIntuition == NULL)
					{
						CloseLibrary(IntuitionBase);
						IntuitionBase = NULL;
					}
				}
			}
			#endif /* __amigaos4__ */

			if(IntuitionBase != NULL)
			{
				struct EasyStruct es;
				STRPTR title;

				memset(&es,0,sizeof(es));

				if(NewProgramName != NULL)
					title = NewProgramName;
				else
					title = WBStartup->sm_ArgList[0].wa_Name;

				es.es_StructSize	= sizeof(es);
				es.es_Title			= title;
				es.es_TextFormat	= message;
				es.es_GadgetFormat	= "OK";

				EasyRequestArgs(NULL,&es,NULL,NULL);
			}

			FreeVec(message);
		}

		#if defined(__amigaos4__)
		{
			if(IIntuition != NULL)
			{
				DropInterface((struct Interface *)IIntuition);
				IIntuition = NULL;
			}
		}
		#endif /* __amigaos4__ */

		CloseLibrary(IntuitionBase);
		IntuitionBase = NULL;
	}
}

/* Add another error message to the list; the messages are
 * collected so that they may be displayed together when
 * necessary.
 */
static void
add_error_message(const TEXT * fmt,APTR args)
{
	int size;

	size = CVSPrintf(fmt,args);
	if(size > 0)
	{
		struct MinNode * mn;

		mn = AllocVec(sizeof(*mn) + size,MEMF_ANY|MEMF_PUBLIC);
		if(mn != NULL)
		{
			STRPTR msg = (STRPTR)(mn + 1);

			LocalVSNPrintf(msg,size,fmt,args);

			AddTail((struct List *)&ErrorList,(struct Node *)mn);
		}
	}
}

/****************************************************************************/

/* Report an error that has occured; if the program was not launched
 * from Shell, error messages will be accumulated for later display.
 */
void VARARGS68K
report_error(const TEXT * fmt,...)
{
	if(NOT Quiet)
	{
		va_list args;

		/* If this program was started from Workbench the
		 * error messages will be collected for later
		 * display.
		 */
		if(WBStartup != NULL)
		{
			#if defined(__amigaos4__)
			{
				va_startlinear(args,fmt);
				add_error_message(fmt,va_getlinearva(args,APTR));
				va_end(args);
			}
			#else
			{
				va_start(args,fmt);
				add_error_message(fmt,args);
				va_end(args);
			}
			#endif /* __amigaos4__ */
		}
		else
		{
			struct Process * this_process = (struct Process *)FindTask(NULL);
			TEXT program_name[MAX_FILENAME_LEN+1];
			BOOL close_output = FALSE;
			BPTR output;

			GetProgramName(program_name,sizeof(program_name));

			/* Print the error message on the standard error output
			 * stream?
			 */
			if(ErrorOutput == NULL)
			{
				/* Do we have a valid error output stream? This
				 * likely won't work with the V36-V40 shell, but
				 * we check this anyway.
				 */
				if(this_process->pr_CES != ZERO)
				{
					output = this_process->pr_CES;
				}
				/* So we need to try to write straight to the
				 * output window.
				 */
				else
				{
					/* Can we write straight to the output window? */
					output = Open("CONSOLE:", MODE_NEWFILE);
					if(output != ZERO)
					{
						SetVBuf(output, NULL, BUF_LINE, 512);

						close_output = TRUE;
					}
					/* Fall back to using the standard output stream. */
					else
					{
						output = Output();
					}
				}
			}
			/* No, we use the standard output stream. */
			else
			{
				output = Output();
			}

			if(output != ZERO)
			{
				LocalFPrintf(output, "%s: ",FilePart(program_name));

				#if defined(__amigaos4__)
				{
					va_startlinear(args,fmt);
					VFPrintf(output, fmt, va_getlinearva(args,APTR));
					va_end(args);
				}
				#else
				{
					va_start(args,fmt);
					VFPrintf(output,fmt,args);
					va_end(args);
				}
				#endif /* __amigaos4__ */

				LocalFPrintf(output, "\n");

				if(close_output)
					Close(output);
			}
		}
	}
}

/****************************************************************************/

/* Release memory allocated from the global pool. */
void
free_memory(APTR address)
{
	if(address != NULL)
	{
		ULONG * mem = address;
		ULONG size = mem[-1];

		#if DEBUG
		{
			total_memory_allocated -= size;

			if(GETDEBUGLEVEL() > 0)
			{
				ASSERT( size >= sizeof(*mem) );

				memset(address,0xA3,size - sizeof(*mem));
			}
		}
		#endif /* DEBUG */

		FreePooled(MemoryPool,&mem[-1],size);
	}
}

/* Allocate memory from the global pool. */
APTR
allocate_memory(LONG size)
{
	APTR result = NULL;

	if(size > 0)
	{
		ULONG * mem;

		size = sizeof(*mem) + ((size + 7) & ~7UL);

		mem = AllocPooled(MemoryPool,size);
		if(mem != NULL)
		{
			(*mem++) = size;

			#if DEBUG
			{
				if(GETDEBUGLEVEL() > 0)
				{
					ASSERT( mem[-1] >= sizeof(*mem) );

					memset(mem,0xA5,mem[-1] - sizeof(*mem));
				}

				total_memory_allocated += size;
				if(max_memory_allocated < total_memory_allocated)
					max_memory_allocated = total_memory_allocated;
			}
			#endif /* DEBUG */

			result = mem;
		}
	}

	return(result);
}

/****************************************************************************/

/* Allocate memory for a new lock node and initialize it. */
static struct LockNode *
allocate_lock_node(
	LONG					access_mode,
	const TEXT *			full_name,
	const struct MsgPort *	user)
{
	struct LockNode * ln;

	ln = allocate_memory(sizeof(*ln));
	if(ln != NULL)
	{
		memset(ln,0,sizeof(*ln));

		ln->ln_FileLock.fl_Key		= (LONG)ln;
		ln->ln_Magic				= ID_SMB_DISK;
		ln->ln_FileLock.fl_Access	= access_mode;
		ln->ln_FileLock.fl_Task		= FileSystemPort;
		ln->ln_FileLock.fl_Volume	= MKBADDR(VolumeNode);
		ln->ln_FullName				= (TEXT *)full_name;
		ln->ln_LastUser				= user;
	}

	return(ln);
}

/****************************************************************************/

/* Allocate memory for a new file node and initialize it. */
static struct FileNode *
allocate_file_node(
	LONG						mode,
	const TEXT *				full_name,
	const struct FileHandle *	fh,
	const smba_file_t *			file)
{
	struct FileNode * fn;

	fn = allocate_memory(sizeof(*fn));
	if(fn != NULL)
	{
		memset(fn, 0, sizeof(*fn));

		fn->fn_Handle	= (struct FileHandle *)fh;
		fn->fn_Magic	= ID_SMB_DISK;
		fn->fn_Volume	= VolumeNode;
		fn->fn_FullName	= (TEXT *)full_name;
		fn->fn_File		= (smba_file_t *)file;
		fn->fn_Mode		= mode;
	}

	return(fn);
}

/****************************************************************************/

/* Obtain the number of seconds to add to the current time
 * to translate local time into UTC.
 */
LONG
get_time_zone_delta(void)
{
	LONG seconds;

	if(OverrideLocaleTimeZone)
	{
		seconds = 60 * TimeZoneOffset;
	}
	else if (Locale != NULL)
	{
		/* The GMT offset actually is the number of minutes to add to
		 * the local time to yield Greenwich Mean Time. It is negative
		 * for all time zones east of the Greenwich meridian and
		 * positive for all time zones west of it.
		 */
		seconds = 60 * Locale->loc_GMTOffset;
	}
	else
	{
		seconds = 0;
	}

	D(("time zone offset: %ld + %ld = %ld",seconds,DSTOffset,seconds + DSTOffset));

	return(seconds + DSTOffset);
}

/****************************************************************************/

/* Obtain the current time, in standard Unix format, adjusted for the
 * local time zone.
 */
ULONG
get_current_time(void)
{
	struct timeval tv;
	ULONG result;

	GetSysTime((APTR)&tv);

	result = tv.tv_secs + UNIX_TIME_OFFSET + get_time_zone_delta();

	return(result);
}

/****************************************************************************/

/* Fill in a 'tm' type time specification with time information
 * corresponding to the number of seconds provided. Input is
 * in Unix format.
 */
void
seconds_to_tm(time_t seconds,struct tm * tm)
{
	struct ClockData clock_data;

	if(seconds < UNIX_TIME_OFFSET)
		seconds = 0;
	else
		seconds -= UNIX_TIME_OFFSET;

	Amiga2Date(seconds,&clock_data);

	memset(tm,0,sizeof(*tm));

	tm->tm_sec	= clock_data.sec;
	tm->tm_min	= clock_data.min;
	tm->tm_hour	= clock_data.hour;
	tm->tm_mday	= clock_data.mday;
	tm->tm_mon	= clock_data.month - 1;
	tm->tm_year	= clock_data.year - 1900;
}

/* Calculate the number of seconds that have passed since January 1st 1970
 * based upon the time specification provided. Output is in Unix format.
 */
time_t
tm_to_seconds(const struct tm * const tm)
{
	struct ClockData clock_data;
	time_t seconds;

	clock_data.sec		= tm->tm_sec;
	clock_data.min		= tm->tm_min;
	clock_data.hour		= tm->tm_hour;
	clock_data.mday		= tm->tm_mday;
	clock_data.month	= tm->tm_mon + 1;
	clock_data.year		= tm->tm_year + 1900;

	seconds = Date2Amiga(&clock_data) + UNIX_TIME_OFFSET;

	return(seconds);
}

/****************************************************************************/

/* This is used by the CVSPrintf() and LocalSNPrintf() functions below. */
struct FormatContext
{
	TEXT *	fc_Buffer;	/* Where to store the next character. */
	int		fc_Limit;	/* How many more characters may be stored. */
	int		fc_Size;	/* How many characters were stored so far. */
};

/****************************************************************************/

/* We just count the number of characters here. Note that this function
 * has two parameters and uses only one: this is needed for OS4 for which
 * RawDoFmt() always passes both.
 */
static void ASM
CountChar(REG(d0,TEXT unused_c),REG(a3,struct FormatContext * fc))
{
	fc->fc_Size++;
}

/* Count the number of characters LocalSNPrintf() would put into a string.
 * Note that this includes the terminating NUL character.
 */
static LONG
CVSPrintf(const TEXT * format_string,APTR args)
{
	struct FormatContext fc;

	fc.fc_Size = 0;

	RawDoFmt((STRPTR)format_string,args,(void (*)())CountChar,&fc);

	return(fc.fc_Size);
}

/****************************************************************************/

/* Store the next character in the buffer, but only if there is still room. */
static void ASM
StuffChar(REG(d0,TEXT c),REG(a3,struct FormatContext * fc))
{
	if(fc->fc_Limit > 0)
	{
		(*fc->fc_Buffer++) = c;

		fc->fc_Size++;

		fc->fc_Limit--;
	}
}

/* This is the non-varargs variant of LocalSNPrintf() below. */
static int
LocalVSNPrintf(STRPTR buffer, int limit, const TEXT * formatString, APTR args)
{
	struct FormatContext fc;

	fc.fc_Buffer	= buffer;
	fc.fc_Limit		= limit-1;	/* One less character for terminating NUL. */
	fc.fc_Size		= 0;

	RawDoFmt(formatString,args,(void (*)())StuffChar,&fc);

	if(limit > 0)
		(*fc.fc_Buffer) = '\0';

	return(fc.fc_Size);
}

/****************************************************************************/

/* Format a string for output. The number of characters which may be
 * stored in the string cannot exceed what the limit parameter states.
 * Unless limit is 0, the string will be NUL-terminated.
 */
void VARARGS68K
LocalSNPrintf(STRPTR buffer, int limit, const TEXT * formatString,...)
{
	va_list varArgs;

	#if defined(__amigaos4__)
	{
		va_startlinear(varArgs,formatString);
		LocalVSNPrintf(buffer,limit,formatString,va_getlinearva(varArgs,APTR));
		va_end(varArgs);
	}
	#else
	{
		va_start(varArgs,formatString);
		LocalVSNPrintf(buffer,limit,formatString,varArgs);
		va_end(varArgs);
	}
	#endif /* __amigaos4__ */
}

/****************************************************************************/

/* NetBIOS broadcast name query code courtesy of Christopher R. Hertel.
 * Thank you very much, Chris!
 */
struct addr_entry
{
	unsigned short flags;
	unsigned char address[4];
};

struct nmb_header
{
	unsigned short name_trn_id;
	unsigned short flags;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
};

static void
L1_Encode(UBYTE * dst, const UBYTE * name, const UBYTE pad, const UBYTE sfx)
{
	int i = 0;
	int j = 0;
	int k;

	while(('\0' != name[i]) && (i < 15))
	{
		k = ToUpper(name[i]);
		i++;
		dst[j++] = 'A' + ((k & 0xF0) >> 4);
		dst[j++] = 'A' + (k & 0x0F);
	}

	i = 'A' + ((pad & 0xF0) >> 4);
	k = 'A' + (pad & 0x0F);

	while(j < 30)
	{
		dst[j++] = i;
		dst[j++] = k;
	}

	dst[30] = 'A' + ((sfx & 0xF0) >> 4);
	dst[31] = 'A' + (sfx & 0x0F);
	dst[32] = '\0';
}

static int
L2_Encode(UBYTE * dst, const UBYTE * name, const UBYTE pad, const UBYTE sfx, const UBYTE * scope)
{
	int lenpos;
	int i;
	int j;

	L1_Encode(&dst[1], name, pad, sfx);

	dst[0] = 0x20;
	lenpos = 33;

	if('\0' != (*scope))
	{
		do
		{
			for(i = 0, j = (lenpos + 1);
			    ('.' != scope[i]) && ('\0' != scope[i]);
			    i++, j++)
			{
				dst[j] = ToUpper(scope[i]);
			}

			dst[lenpos] = (UBYTE)i;
			lenpos += i + 1;
			scope += i;
		}
		while('.' == (*scope++));

		dst[lenpos] = '\0';
	}

	return(lenpos + 1);
}

int
BroadcastNameQuery(const char *name, const char *scope, UBYTE *address)
{
	static const UBYTE header[12] =
	{
		0x07, 0xB0,	/* 1964 == 0x07B0. */
		0x01, 0x10,	/* Binary 0 0000 0010001 0000 */
		0x00, 0x01,	/* One name query. */
		0x00, 0x00,	/* Zero answers. */
		0x00, 0x00,	/* Zero authorities. */
		0x00, 0x00	/* Zero additional. */
	};

	static const UBYTE query_tail[4] =
	{
		0x00, 0x20,
		0x00, 0x01
	};

	struct timeval tv;
	fd_set read_fds;
	int sock_fd;
	int option_true = 1;
	struct sockaddr_in sox;
	struct nmb_header nmb_header;
	UBYTE buffer[512];
	int total_len;
	int i,n;
	int result;
	struct servent * s;

	ENTER();

	PROFILE_OFF();

	sock_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock_fd < 0)
	{
		SHOWMSG("couldn't get the socket");
		result = errno;
		goto out;
	}

	if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &option_true, sizeof(option_true)) < 0)
	{
		SHOWMSG("couldn't enable the broadcast option");
		result = errno;
		goto out;
	}

	memset(&sox,0,sizeof(sox));

	sox.sin_family = AF_INET;
	sox.sin_addr.s_addr = htonl(0xFFFFFFFF);

	s = getservbyname("netbios-ns","udp");
	if(s != NULL)
		sox.sin_port = s->s_port;
	else
		sox.sin_port = htons(137);

	memcpy(buffer, header, (total_len = sizeof(header)));

	n = L2_Encode(&buffer[total_len], name, ' ', '\0', scope);
	total_len += n;

	ASSERT( total_len <= (int)sizeof(buffer) );

	memcpy(&buffer[total_len], query_tail, sizeof(query_tail));
	total_len += sizeof(query_tail);

	ASSERT( total_len <= (int)sizeof(buffer) );

	result = ENOENT;
	n = 0;

	/* Send the query packet; retry five times with a one second
	 * delay in between.
	 */
	for(i = 0 ; i < 5 ; i++)
	{
		if(sendto(sock_fd, (void *) buffer, total_len, 0, (struct sockaddr *)&sox, sizeof(struct sockaddr_in)) < 0)
		{
			SHOWMSG("could not send the packet");
			result = errno;
			goto out;
		}

		/* Wait for a response to arrive. */
		tv.tv_secs = 1;
		tv.tv_micro = 0;

		FD_ZERO(&read_fds);
		FD_SET(sock_fd,&read_fds);

		if(WaitSelect(sock_fd+1, &read_fds, NULL, NULL, &tv, NULL) > 0)
		{
			n = recv(sock_fd, buffer, sizeof(buffer), 0);
			if(n < 0)
			{
				SHOWMSG("could not pick up the response packet");
				result = errno;
				goto out;
			}
			else if (n > 0)
			{
				break;
			}
		}
	}

	/* Did we get anything at all? */
	if(n > (int)sizeof(nmb_header))
	{
		/* Check whether the query was successful. */
		memcpy(&nmb_header, buffer, sizeof(nmb_header));
		if((nmb_header.flags & 0xF) == OK)
		{
			/* Find the NB/IP fields which directly follow
			 * the name.
			 */
			for(i = sizeof(header) + strlen(&buffer[sizeof(header)])+1 ;
			    i < n - (int)sizeof(query_tail) ;
			    i++)
			{
				if(memcmp(&buffer[i], query_tail, sizeof(query_tail)) == SAME)
				{
					int start;

					/* This should be the start of the interesting bits;
					 * we skip the NB/IP fields and the TTL field.
					 */
					start = i + sizeof(query_tail) + sizeof(long);
					if(start < n)
					{
						unsigned short read_len;
						struct addr_entry addr_entry;

						/* This should be the read length. */
						memcpy(&read_len, &buffer[start], 2);

						/* Is there any useful and readable data attached? */
						if(read_len >= sizeof(addr_entry) &&
						   start + (int)sizeof(read_len) + (int)sizeof(addr_entry) <= n)
						{
							/* Copy a single address entry; this should be
							 * just the one we need.
							 */
							memcpy(&addr_entry, &buffer[start + sizeof(read_len)], sizeof(addr_entry));

							/* Copy the address field (IPv4 only). */
							memcpy(address, addr_entry.address, 4);

							result = 0;
						}
					}

					break;
				}
			}
		}
	}

 out:

	if(sock_fd >= 0)
		CloseSocket(sock_fd);

	PROFILE_ON();

	RETURN(result);
	return(result);
}

/* This is the counterpart to the BroadcastNameQuery() function
 * which not only retrieves the name of the workstation, but also
 * the name of the workgroup, if possible.
 */
int
SendNetBIOSStatusQuery(
	struct sockaddr_in	sox,
	char *				server_name,
	int					server_name_size,
	char *				workgroup_name,
	int					workgroup_name_size)
{
	static const UBYTE query[] =
	{
		0x07, 0xB2,	/* 1970 == 0x07B2. */
		0x00, 0x00,	/* Binary 0 0000 0010001 0000 */
		0x00, 0x01,	/* One name query. */
		0x00, 0x00,	/* Zero answers. */
		0x00, 0x00,	/* Zero authorities. */
		0x00, 0x00,	/* Zero additional. */

		/* Question name: "*" padded with \0 bytes, layer 2 encoded, NUL-terminated. */
		0x20,	/* NetBIOS name format. */
		0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,

		/* Question type: NBSTAT = 33 (NetBIOS status query) */
		0x00, 0x21,

		/* Question class: IN = 1 */
		0x00, 0x01
	};

	static const UBYTE query_tail[4] =
	{
		0x00, 0x21,
		0x00, 0x01
	};

	struct timeval tv;
	fd_set read_fds;
	int sock_fd;
	struct nmb_header nmb_header;
	UBYTE buffer[512];
	int i,n;
	int result;
	struct servent * s;

	ENTER();

	PROFILE_OFF();

	if(server_name != NULL && server_name_size > 0)
	{
		server_name_size--;
		server_name[0] = '\0';
	}

	if(workgroup_name != NULL && workgroup_name_size > 0)
	{
		workgroup_name_size--;
		workgroup_name[0] = '\0';
	}

	sock_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(sock_fd < 0)
	{
		SHOWMSG("couldn't get the socket");
		result = errno;
		goto out;
	}

	s = getservbyname("netbios-ns","udp");
	if(s != NULL)
		sox.sin_port = s->s_port;
	else
		sox.sin_port = htons(137);

	result = ENOENT;
	n = 0;

	/* Send the query packet; retry five times with a one second
	 * delay in between.
	 */
	for(i = 0 ; i < 5 ; i++)
	{
		if(sendto(sock_fd, (void *) query, sizeof(query), 0, (struct sockaddr *)&sox, sizeof(sox)) < 0)
		{
			SHOWMSG("could not send the packet");
			result = errno;
			goto out;
		}

		/* Wait for a response to arrive. */
		tv.tv_secs = 1;
		tv.tv_micro = 0;

		FD_ZERO(&read_fds);
		FD_SET(sock_fd,&read_fds);

		if(WaitSelect(sock_fd+1, &read_fds, NULL, NULL, &tv, NULL) > 0)
		{
			n = recv(sock_fd, buffer, sizeof(buffer), 0);
			if(n < 0)
			{
				SHOWMSG("could not pick up the response packet");
				result = errno;
				goto out;
			}
			else if (n > 0)
			{
				break;
			}
		}
	}

	/* Did we get anything at all? */
	if(n > (int)sizeof(nmb_header))
	{
		/* Check whether the query was successful, is a response,
		 * and if there is an answer in it.
		 */
		memcpy(&nmb_header, buffer, sizeof(nmb_header));

		D(("status = %ld", (nmb_header.flags & 0xF)));
		D(("is response = %s", (nmb_header.flags & 0x8000) ? "yes" : "no"));
		D(("number of answers = %ld", nmb_header.ancount));

		if((nmb_header.flags & 0xF) == OK &&
		   (nmb_header.flags & 0x8000) != 0 &&
		   nmb_header.ancount > 0)
		{
			/* Find the NB/IP fields which directly follow
			 * the name.
			 */
			for(i = sizeof(nmb_header) + strlen(&buffer[sizeof(nmb_header)])+1 ;
			    i < n - (int)sizeof(query_tail) ;
			    i++)
			{
				if(memcmp(&buffer[i], query_tail, sizeof(query_tail)) == SAME)
				{
					int start;

					SHOWMSG("found a response");

					/* This should be the start of the interesting bits;
					 * we skip the NB/IP fields and the TTL field.
					 */
					start = i + sizeof(query_tail) + sizeof(long);
					if(start < n)
					{
						unsigned short data_length;

						/* Get the data length. */
						memcpy(&data_length, &buffer[start], 2);
						start += 2;

						SHOWVALUE(data_length);

						if(data_length > 0 && start + data_length <= n)
						{
							int number_of_names;

							number_of_names = buffer[start++];

							SHOWVALUE(number_of_names);

							if(number_of_names > 0)
							{
								const char * server_name_record = NULL;
								const char * workgroup_name_record = NULL;
								const char * s;
								unsigned short flags;
								int type;
								int j, l;

								for(j = 0 ;
								    j < number_of_names && (server_name_record == NULL || workgroup_name_record == NULL) ;
									j++)
								{
									l = 15;

									s = (char *)&buffer[start];
									start += l;

									/* Remove padding. */
									while(l > 0 && s[l-1] == ' ')
										l--;

									type = buffer[start++];

									memcpy(&flags, &buffer[start], 2);
									start += 2;

									#if DEBUG
									{
										TEXT name_copy[20];

										if(l > sizeof(name_copy)-1)
											l = sizeof(name_copy)-1;

										memcpy(name_copy,s,l);
										name_copy[l] = '\0';

										D(("name='%s', len=%ld, type=%ld, flags=0x%04lx", name_copy, l, type, flags));
									}
									#endif /* DEBUG */

									/* Not a group name, and name is active? */
									if((flags & 0x8400) == 0x0400)
									{
										if(type == 0x00) /* workstation/redirector */
										{
											if(server_name_record == NULL)
											{
												server_name_record = s;

												if(server_name != NULL && server_name_size > 0)
												{
													if(l > server_name_size)
														l = server_name_size;

													memcpy(server_name, s, l);
													server_name[l] = '\0';

													D(("server name is '%s'", server_name));
												}

												result = OK;
											}
										}
									}
									/* Group name, and name is active? */
									else if ((flags & 0x8400) == 0x8400)
									{
										if(type == 0x00) /* workstation/redirector */
										{
											if(workgroup_name_record == NULL)
											{
												workgroup_name_record = s;

												if(workgroup_name != NULL && workgroup_name_size > 0)
												{
													if(l > workgroup_name_size)
														l = workgroup_name_size;

													memcpy(workgroup_name, s, l);
													workgroup_name[l] = '\0';

													D(("workgroup name is '%s'", workgroup_name));
												}

												result = OK;
											}
										}
									}
								}
							}
						}
						else
						{
							SHOWMSG("too much data");
						}
					}
					else
					{
						SHOWMSG("nothing useful in there");
					}

					break;
				}
			}
		}
	}
	else
	{
		D(("didn't receive anything useful (n=%ld)", n));
	}

 out:

	if(sock_fd >= 0)
		CloseSocket(sock_fd);

	PROFILE_ON();

	RETURN(result);
	return(result);
}

/****************************************************************************/

/* Send a disk change notification message which will be picked up
 * by all applications that listen for this kind of event, e.g.
 * Workbench.
 */
static void
send_disk_change_notification(ULONG class)
{
	struct IOStdReq * input_request = NULL;
	struct MsgPort * input_port;
	struct InputEvent ie;

	ENTER();

	PROFILE_OFF();

	input_port = CreateMsgPort();
	if(input_port == NULL)
		goto out;

	input_request = (struct IOStdReq *)CreateIORequest(input_port,sizeof(*input_request));
	if(input_request == NULL)
		goto out;

	if(OpenDevice("input.device",0,(struct IORequest *)input_request,0) != OK)
		goto out;

	memset(&ie,0,sizeof(ie));

	ie.ie_Class		= class;
	ie.ie_Qualifier	= IEQUALIFIER_MULTIBROADCAST;

	GetSysTime(&ie.ie_TimeStamp);

	input_request->io_Command	= IND_WRITEEVENT;
	input_request->io_Data		= &ie;
	input_request->io_Length	= sizeof(ie);

	DoIO((struct IORequest *)input_request);

 out:

	if(input_request != NULL)
	{
		if(input_request->io_Device != NULL)
			CloseDevice((struct IORequest *)input_request);

		DeleteIORequest((struct IORequest *)input_request);
	}

	DeleteMsgPort(input_port);

	PROFILE_ON();

	LEAVE();
}

/****************************************************************************/

/* Find the file node corresponding to a given name,
 * skipping a particular entry if necessary.
 */
static struct FileNode *
find_file_node_by_name(const TEXT * name,const struct FileNode * skip)
{
	struct FileNode * result = NULL;
	struct FileNode * fn;

	ASSERT( name != NULL );

	#ifndef USE_SPLAY_TREE
	{
		D(("searching for file with name '%s'", name));

		for(fn = (struct FileNode *)FileList.mlh_Head ;
		    fn->fn_MinNode.mln_Succ != NULL ;
		    fn = (struct FileNode *)fn->fn_MinNode.mln_Succ)
		{
			if(fn != skip && compare_names(name,fn->fn_FullName) == SAME)
			{
				result = fn;
				break;
			}
		}

		if(result != NULL)
			D(("found it (= 0x%08lx)", result));
		else
			SHOWMSG("didn't find it");
	}
	#else
	{
		struct splay_node * sn;

		D(("looking up file with name '%s'", name));

		/* Find the list of all files which match the given name. */
		sn = splay_tree_find(&FileNameTree, (splay_key_t)name);
		if(sn != NULL)
		{
			fn = (struct FileNode *)sn->sn_userdata;

			ASSERT( fn != NULL );

			/* Use this entry, unless it's the one which we
			 * wanted to skip.
			 */
			if (fn != skip)
			{
				result = fn;

				D(("found it (= 0x%08lx)", (ULONG)result));
			}
			/* Use the next entry in the list, if possible. */
			else if (sn->sn_next != NULL)
			{
				result = (struct FileNode *)sn->sn_next->sn_userdata;

				D(("found it, but can't use it, so using the next best entry (= 0x%08lx)", (ULONG)result));

				if(result == NULL)
					SHOWMSG("...but didn't actually find it");
			}
			else
			{
				SHOWMSG("didn't find it");
			}
		}
		else
		{
			SHOWMSG("didn't find it");
		}
	}
	#endif /* USE_SPLAY_TREE */

	return(result);
}

/* Find the lock node corresponding to a given name,
 * skipping a particular entry if necessary.
 */
static struct LockNode *
find_lock_node_by_name(const TEXT * name,const struct LockNode * skip)
{
	struct LockNode * result = NULL;
	struct LockNode * ln;

	#ifndef USE_SPLAY_TREE
	{
		D(("searching for lock with name '%s'", name));

		for(ln = (struct LockNode *)LockList.mlh_Head ;
		    ln->ln_MinNode.mln_Succ != NULL ;
		    ln = (struct LockNode *)ln->ln_MinNode.mln_Succ)
		{
			if(ln != skip && compare_names(name,ln->ln_FullName) == SAME)
			{
				result = ln;
				break;
			}
		}

		if(result != NULL)
			D(("found it (= 0x%08lx)", result));
		else
			SHOWMSG("didn't find it");
	}
	#else
	{
		struct splay_node * sn;

		D(("looking up lock with name '%s'", name));

		sn = splay_tree_find(&LockNameTree, (splay_key_t)name);
		if(sn != NULL)
		{
			ln = (struct LockNode *)sn->sn_userdata;

			ASSERT( ln != NULL );

			if (ln != skip)
			{
				result = ln;

				D(("found it (= 0x%08lx)", (ULONG)result));
			}
			else if (sn->sn_next != NULL)
			{
				result = (struct LockNode *)sn->sn_next->sn_userdata;

				D(("found it, but can't use it, so using the next best entry (= 0x%08lx)", (ULONG)result));

				if(result == NULL)
					SHOWMSG("...but didn't actually find it");
			}
			else
			{
				SHOWMSG("didn't find it");
			}
		}
		else
		{
			SHOWMSG("didn't find it");
		}
	}
	#endif /* USE_SPLAY_TREE */

	return(result);
}

/* Check whether a new reference to be made to a named
 * file will cause a conflict of access modes. No two
 * files and locks may refer to the same object if
 * either of these references is made in exclusive
 * mode. This is the case which this function is
 * trying to avoid.
 */
static int
check_access_mode_collision(const TEXT * name,LONG mode)
{
	int error = ERROR_OBJECT_IN_USE;
	struct LockNode * ln;
	struct FileNode * fn;

	ENTER();

	D(("name = '%s'", escape_name(name)));

	fn = find_file_node_by_name(name,NULL);
	if(fn != NULL)
	{
		if(mode != SHARED_LOCK || fn->fn_Mode != SHARED_LOCK)
		{
			D(("collides with '%s'",escape_name(fn->fn_FullName)));
			goto out;
		}
	}

	ln = find_lock_node_by_name(name,NULL);
	if(ln != NULL)
	{
		if(mode != SHARED_LOCK || ln->ln_FileLock.fl_Access != SHARED_LOCK)
		{
			D(("collides with '%s'",escape_name(ln->ln_FullName)));
			goto out;
		}
	}

	error = OK;

 out:

	RETURN(error);
	return(error);
}

/* Find out whether there already exists a reference to a
 * certain file or directory. Returns an AmigaDOS error
 * code if so, and 0 otherwise.
 */
static int
name_already_in_use(const TEXT * name)
{
	int error = ERROR_OBJECT_IN_USE;

	ENTER();

	SHOWSTRING(name);

	if(find_file_node_by_name(name,NULL))
	{
		SHOWMSG("found a file by that name");
		goto out;
	}

	if(find_lock_node_by_name(name,NULL) != NULL)
	{
		SHOWMSG("found a lock by that name");
		goto out;
	}

	error = OK;

 out:

	RETURN(error);
	return(error);
}

/* Check whether an AmigaDOS path name uses special characters which should be
 * avoided when used with the SMB file sharing protocol. This test accepts '/'
 * and ':' as valid characters that may appear in an AmigaDOS path name.
 *
 * Reserved characters are control codes in the range 0..31, as well as
 * '<' (less than), '>' (greater than), ':' (colon), '"' (double quote),
 * '/' (forward slash), '\' (backslash), '|' (vertical bar or pipe),
 * '?' (question mark) and '*' (asterisk). The '?' and '*' are the MS-DOS
 * wildcard pattern characters which the SMB delete and rename commands
 * would process if they were part of the "file name".
 *
 * This list can be found (2018-12-28) here:
 *    https://docs.microsoft.com/en-us/windows/desktop/fileio/naming-a-file
 *
 * We also reject the use of "." and ".." as path names.
 */
static BOOL
path_name_is_invalid(const TEXT * name, int name_len)
{
	BOOL result = TRUE;
	TEXT c;
	int i;

	/* Disallow "." and "..". */
	if((name_len == 1 && name[0] == '.') || (name_len == 1 && name[0] == '.' && name[1] == '.'))
		goto out;

	for(i = 0 ; i < name_len ; i++)
	{
		c = name[i];

		if(c < ' ' || strchr("<>\"\\|?*", c) != NULL)
			goto out;
	}

	result = FALSE;

 out:

	return(result);
}

/****************************************************************************/

/* Convert a POSIX error code into an AmigaDOS error code. */
static LONG
map_errno_to_ioerr(int error)
{
	/* Not all of these mappings make good sense; bear in mind that
	 * POSIX covers more than a hundred different error codes
	 * whereas with AmigaDOS we're stranded with a measly 48...
	 */
	static const int map_posix_to_amigados[][2] =
	{
		{ E2BIG,			ERROR_TOO_MANY_ARGS },			/* Argument list too long */
		{ EACCES,			ERROR_READ_PROTECTED },			/* Permission denied */
		{ EADDRINUSE,		ERROR_OBJECT_IN_USE },			/* Address already in use */
		{ EADDRNOTAVAIL,	ERROR_DIR_NOT_FOUND },			/* Can't assign requested address */
		{ EAFNOSUPPORT,		ERROR_NOT_IMPLEMENTED },		/* Address family not supported by protocol family */
		{ EAGAIN, 			ERROR_LOCK_TIMEOUT },			/* Resource temporarily unavailable */
		{ EBADF,			ERROR_INVALID_LOCK },			/* Bad file descriptor */
		{ EBUSY,			ERROR_OBJECT_IN_USE },			/* Device busy */
		{ ECONNABORTED,		ERROR_DIR_NOT_FOUND },			/* Software caused connection abort */
		{ ECONNREFUSED,		ERROR_OBJECT_IN_USE },			/* Connection refused */
		{ ECONNRESET,		ERROR_DIR_NOT_FOUND },			/* Connection reset by peer */
		{ EDEADLK,			ERROR_READ_PROTECTED },			/* Resource deadlock avoided */
		{ EDESTADDRREQ,		ERROR_REQUIRED_ARG_MISSING },	/* Destination address required */
		{ EDQUOT,			ERROR_DISK_FULL },				/* Disc quota exceeded */
		{ EEXIST,			ERROR_OBJECT_EXISTS },			/* File exists */
		{ EFAULT,			ERROR_BAD_NUMBER },				/* Bad address */
		{ EFBIG,			ERROR_OBJECT_IN_USE },			/* File too large */
		{ EHOSTDOWN,		ERROR_DIR_NOT_FOUND },			/* Host is down */
		{ EHOSTUNREACH,		ERROR_DIR_NOT_FOUND },			/* No route to host */
		{ EINTR,			ERROR_BREAK },					/* Interrupted system call */
		{ EINVAL,			ERROR_BAD_NUMBER },				/* Invalid argument */
		{ EIO,				ERROR_OBJECT_IN_USE },			/* Input/output error */
		{ EISCONN,			ERROR_OBJECT_IN_USE },			/* Socket is already connected */
		{ EISDIR,			ERROR_OBJECT_WRONG_TYPE },		/* Is a directory */
		{ ELOOP,			ERROR_TOO_MANY_LEVELS },		/* Too many levels of symbolic links */
		{ EMFILE,			ERROR_NO_FREE_STORE },			/* Too many open files */
		{ EMLINK,			ERROR_TOO_MANY_LEVELS },		/* Too many links */
		{ EMSGSIZE,			ERROR_LINE_TOO_LONG },			/* Message too long */
		{ ENAMETOOLONG,		ERROR_LINE_TOO_LONG },			/* File name too long */
		{ ENETDOWN,			ERROR_DIR_NOT_FOUND },			/* Network is down */
		{ ENETRESET,		ERROR_DIR_NOT_FOUND },			/* Network dropped connection on reset */
		{ ENETUNREACH,		ERROR_DIR_NOT_FOUND },			/* Network is unreachable */
		{ ENFILE,			ERROR_NO_FREE_STORE },			/* Too many open files in system */
		{ ENOBUFS,			ERROR_BUFFER_OVERFLOW },		/* No buffer space available */
		{ ENODEV,			ERROR_OBJECT_WRONG_TYPE },		/* Operation not supported by device */
		{ ENOENT,			ERROR_OBJECT_NOT_FOUND },		/* No such file or directory */
		{ ENOLCK,			ERROR_NOT_IMPLEMENTED },		/* no locks available */
		{ ENOMEM,			ERROR_NO_FREE_STORE },			/* Cannot allocate memory */
		{ ENOPROTOOPT,		ERROR_NOT_IMPLEMENTED },		/* Protocol not available */
		{ ENOSPC,			ERROR_DISK_FULL },				/* No space left on device */
		{ ENOTBLK,			ERROR_OBJECT_WRONG_TYPE },		/* Block device required */
		{ ENOTCONN,			ERROR_OBJECT_WRONG_TYPE },		/* Socket is not connected */
		{ ENOTDIR,			ERROR_OBJECT_WRONG_TYPE },		/* Not a directory */
		{ ENOTEMPTY,		ERROR_DIRECTORY_NOT_EMPTY },	/* Directory not empty */
		{ ENOTSOCK,			ERROR_OBJECT_WRONG_TYPE },		/* Socket operation on non-socket */
		{ ENXIO,			ERROR_OBJECT_NOT_FOUND },		/* No such device or address */
		{ EOPNOTSUPP,		ERROR_NOT_IMPLEMENTED },		/* Operation not supported */
		{ EPERM,			ERROR_READ_PROTECTED },			/* Operation not permitted */
		{ EPFNOSUPPORT,		ERROR_NOT_IMPLEMENTED },		/* Protocol family not supported */
		{ EPROCLIM,			ERROR_TASK_TABLE_FULL },		/* Too many processes */
		{ EPROTONOSUPPORT,	ERROR_NOT_IMPLEMENTED },		/* Protocol not supported */
		{ EPROTOTYPE,		ERROR_BAD_TEMPLATE },			/* Protocol wrong type for socket */
		{ ERANGE,			ERROR_BAD_NUMBER },				/* Numerical result out of range */
		{ EROFS,			ERROR_WRITE_PROTECTED },		/* Read-only file system */
		{ ESHUTDOWN,		ERROR_INVALID_LOCK },			/* Can't send after socket shutdown */
		{ ESOCKTNOSUPPORT,	ERROR_NOT_IMPLEMENTED },		/* Socket type not supported */
		{ ESPIPE,			ERROR_SEEK_ERROR },				/* Illegal seek */
		{ ESRCH,			ERROR_OBJECT_NOT_FOUND },		/* No such process */
		{ ETXTBSY,			ERROR_OBJECT_IN_USE },			/* Text file busy */
		{ EUSERS,			ERROR_TASK_TABLE_FULL },		/* Too many users */
		{ EXDEV,			ERROR_NOT_IMPLEMENTED },		/* Cross-device link */

		{ error_invalid_netbios_session,		ERROR_BUFFER_OVERFLOW },
		{ error_message_exceeds_buffer_size,	ERROR_BUFFER_OVERFLOW },
		{ error_invalid_buffer_format,			ERROR_BAD_NUMBER },
		{ error_data_exceeds_buffer_size,		ERROR_BUFFER_OVERFLOW },
		{ error_invalid_parameter_size,			ERROR_BAD_NUMBER },
		{ error_server_setup_incomplete,		ERROR_INVALID_COMPONENT_NAME },
		{ error_server_connection_invalid,		ERROR_INVALID_COMPONENT_NAME },
		{ error_smb_message_signature_missing,	ERROR_BAD_STREAM_NAME },
		{ error_smb_message_too_short,			ERROR_BAD_STREAM_NAME },
		{ error_smb_message_invalid_command,	ERROR_BAD_STREAM_NAME },
		{ error_smb_message_invalid_word_count,	ERROR_BAD_STREAM_NAME },
		{ error_smb_message_invalid_byte_count,	ERROR_BAD_STREAM_NAME },
		{ error_looping_in_find_next,			ERROR_TOO_MANY_LEVELS },
		{ error_invalid_directory_size,			ERROR_BAD_NUMBER },
		{ error_session_request_failed,			ERROR_INVALID_COMPONENT_NAME },
		{ error_unsupported_dialect,			ERROR_BAD_NUMBER },

		{ -1, -1 }
	};

	#if DEBUG
	int original_error = error;
	#endif /* DEBUG */

	LONG result = ERROR_ACTION_NOT_KNOWN;
	int i;

	ENTER();

	/* Try our best to translate the SMB error class and code into a POSIX
	 * error code...
	 */
	if(error == error_check_smb_error)
	{
		int error_class	= ((struct smb_server *)ServerData)->rcls;
		int error_code	= ((struct smb_server *)ServerData)->err;

		error = smb_errno(error_class, error_code);
	}

	for(i = 0 ; map_posix_to_amigados[i][0] != -1 ; i++)
	{
		if(map_posix_to_amigados[i][0] == error)
		{
			result = map_posix_to_amigados[i][1];
			break;
		}
	}

	#if DEBUG
	{
		TEXT amigados_error_text[256];

		Fault(result,NULL,amigados_error_text,sizeof(amigados_error_text));

		if(original_error == error_check_smb_error)
		{
			int error_class	= ((struct smb_server *)ServerData)->rcls;
			int error_code	= ((struct smb_server *)ServerData)->err;
			char * smb_class_name;
			char * smb_code_text;

			smb_translate_error_class_and_code(error_class,error_code,&smb_class_name,&smb_code_text);

			D(("Translated SMB %ld/%ld (%s/%s) -> POSIX %ld (%s) -> AmigaDOS error %ld (%s)", error_class, error_code, smb_class_name, smb_code_text, error, posix_strerror(error), result, amigados_error_text));
		}
		else
		{
			D(("Translated POSIX %ld (%s) -> AmigaDOS error %ld (%s)", error, posix_strerror(error), result, amigados_error_text));
		}
	}
	#endif /* DEBUG */

	RETURN(result);
	return(result);
}

/****************************************************************************/

/* Check if the name for an AmigaDOS device or volume is not too short,
 * not too long and does not contain unprintable/unsuitable characters.
 */
static BOOL
is_valid_device_name(const TEXT * name, int len)
{
	BOOL result = FALSE;
	int i, c;

	if(len <= 0 || len > 255)
		goto out;

	for(i = 0 ; i < len ; i++)
	{
		c = name[i];

		if(c == '/' || c == ':' || (c < ' ' && c != '\t') || (128 <= c && c < 160))
			goto out;
	}

	result = TRUE;

 out:

	return(result);
}

/****************************************************************************/

/* Check if a file name is right and proper for AmigaDOS use,
 * which excludes the use of unprintable characters, the path
 * delimiters ':' and '/', but also the SMB path delimeter
 * character '\'.
 *
 * Returns ERROR_INVALID_COMPONENT_NAME if the name is
 * unsuitable, 0 otherwise.
 */
static int
validate_amigados_file_name(const TEXT * name,int len)
{
	int error = ERROR_INVALID_COMPONENT_NAME;
	int i, c;

	if(len <= 0 || len > 255)
		goto out;

	if(MaxNameLen > 0 && len > MaxNameLen)
		goto out;

	for(i = 0 ; i < len ; i++)
	{
		c = name[i];

		/* This should be a printable character and none of
		 * the characters reserved by the file system which
		 * should not appear in a file/directory name.
		 */
		if(c == '/' || c == ':' || c == SMB_PATH_SEPARATOR || (c < ' ' && c != '\t') || (128 <= c && c < 160))
			goto out;
	}

	error = OK;

 out:

	return(error);
}

/****************************************************************************/

/* Pick up all the DOS packets waiting to be processed and
 * return them with an error, claiming that the packet cannot
 * be processed. This is used while the file system has been
 * disabled, to avoid packets piling up which are not going
 * to be processed any time soon.
 */
static void
reject_all_pending_packets(struct MsgPort * port)
{
	struct DosPacket * dp;
	struct Message * mn;
	LONG result;

	while((mn = GetMsg(port)) != NULL)
	{
		SHOWMSG("returning pending packet");

		dp = (struct DosPacket *)mn->mn_Node.ln_Name;

		switch(dp->dp_Action)
		{
			case ACTION_READ_LINK:
			case ACTION_SEEK:
			case ACTION_SET_FILE_SIZE:
			case ACTION_READ:
			case ACTION_WRITE:

				result = -1;
				break;

			default:

				result = DOSFALSE;
				break;
		}

		ReplyPkt(dp,result,ERROR_ACTION_NOT_KNOWN);
	}
}

/****************************************************************************/

/* Remove a DosList entry using the proper protocols. Note that
 * this function can fail!
 */
static BOOL
really_remove_dosentry(struct DosList * entry)
{
	struct MsgPort * port;
	struct DosList * dl;
	BOOL success = FALSE;
	int kind,i;

	ENTER();

	if(entry->dol_Type == DLT_DEVICE)
	{
		D(("removing '%b' (device)", entry->dol_Name));
		kind = LDF_DEVICES;
	}
	else
	{
		D(("removing '%b' (volume)", entry->dol_Name));
		kind = LDF_VOLUMES;
	}

	port = entry->dol_Task;

	for(i = 0 ; i < 100 ; i++)
	{
		dl = AttemptLockDosList(LDF_WRITE|kind);

		/* Workaround for dos.library bug present in
		 * Kickstart 2.0 through Kickstart 3.0.
		 */
		if(((ULONG)dl) == 1)
			dl = NULL;

		if(dl != NULL)
		{
			D(("doslist is locked; removing '%b' for good", entry->dol_Name));

			RemDosEntry(entry);

			UnLockDosList(LDF_WRITE|kind);

			success = TRUE;

			break;
		}

		reject_all_pending_packets(port);

		PROFILE_OFF();

		Delay(TICKS_PER_SECOND / 10);

		PROFILE_ON();
	}

	if(NO success)
		SHOWMSG("that didn't work");

	RETURN(success);
	return(success);
}

/****************************************************************************/

/* Release all resources allocated by the setup() routine. */
static void
cleanup(void)
{
	BOOL send_disk_change = FALSE;

	ENTER();

	PROFILE_OFF();

	/* If any errors have cropped up, display them now before
	 * we call it quits.
	 */
	display_error_message_list();

	if(NewProgramName != NULL)
	{
		FreeVec(NewProgramName);
		NewProgramName = NULL;
	}

	if(Parameters != NULL)
	{
		FreeArgs(Parameters);
		Parameters = NULL;
	}

	if(Icon != NULL)
	{
		FreeDiskObject(Icon);
		Icon = NULL;
	}

	if(ServerData != NULL)
	{
		smba_disconnect(ServerData);
		ServerData = NULL;
	}

	if(DeviceNode != NULL)
	{
		if(DeviceNodeAdded)
		{
			SHOWMSG("removing the device node");

			if(really_remove_dosentry(DeviceNode))
			{
				SHOWMSG("freeing the device node");
				FreeDosEntry(DeviceNode);
			}
			else
			{
				SHOWMSG("that didn't work.");
			}
		}
		else
		{
			FreeDosEntry(DeviceNode);
		}

		DeviceNode = NULL;
	}

	if(VolumeNode != NULL)
	{
		if(VolumeNodeAdded)
		{
			SHOWMSG("removing the volume node");

			if(really_remove_dosentry(VolumeNode))
			{
				SHOWMSG("freeing the volume node");
				FreeDosEntry(VolumeNode);

				send_disk_change = TRUE;
			}
			else
			{
				SHOWMSG("that didn't work.");
			}
		}
		else
		{
			FreeDosEntry(VolumeNode);
		}

		VolumeNode = NULL;
	}

	if(FileSystemPort != NULL)
	{
		SHOWMSG("returning all pending packets");

		/* Return all queued packets; there should be none, though. */
		reject_all_pending_packets(FileSystemPort);

		SHOWMSG("done");

		DeleteMsgPort(FileSystemPort);
		FileSystemPort = NULL;
	}

	if(WBStartup == NULL && send_disk_change)
	{
		SHOWMSG("sending a disk removed event");
		send_disk_change_notification(IECLASS_DISKREMOVED);
	}

	SHOWMSG("closing libraries and devices...");

	#if defined(__amigaos4__)
	{
		if(ITimer != NULL)
		{
			DropInterface((struct Interface *)ITimer);
			ITimer = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(TimerRequest != NULL)
	{
		if(TimerTicking)
		{
			if(CheckIO((struct IORequest *)TimerRequest) == NULL)
				AbortIO((struct IORequest *)TimerRequest);

			WaitIO((struct IORequest *)TimerRequest);
			TimerTicking = FALSE;
		}

		if(TimerRequest->tr_node.io_Device != NULL)
			CloseDevice((struct IORequest *)TimerRequest);

		DeleteIORequest((struct IORequest *)TimerRequest);
		TimerRequest = NULL;
	}

	if(TimerPort != NULL)
		DeleteMsgPort(TimerPort);

	#if defined(__amigaos4__)
	{
		if(ISocket != NULL)
		{
			DropInterface((struct Interface *)ISocket);
			ISocket = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(SocketBase != NULL)
	{
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}

	#if defined(__amigaos4__)
	{
		if(IIcon != NULL)
		{
			DropInterface((struct Interface *)IIcon);
			IIcon = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(IconBase != NULL)
	{
		CloseLibrary(IconBase);
		IconBase = NULL;
	}

	if(Locale != NULL)
	{
		CloseLocale(Locale);
		Locale = NULL;
	}

	#if defined(__amigaos4__)
	{
		if(ILocale != NULL)
		{
			DropInterface((struct Interface *)ILocale);
			ILocale = NULL;
		}
	}
	#endif /* __amigaos4__ */

	if(LocaleBase != NULL)
	{
		CloseLibrary(LocaleBase);
		LocaleBase = NULL;
	}

	if(MemoryPool != NULL)
	{
		DeletePool(MemoryPool);
		MemoryPool = NULL;
	}

	PROFILE_ON();

	LEAVE();
}

/*****************************************************************************/

#ifdef USE_SPLAY_TREE

/* This is used by the splay tree functions to compare the
 * file and lock node addresses.
 */
static int
compare_file_or_lock_by_address(const BYTE * a, const BYTE * b)
{
	int result;

	if (a < b)
		result = -1;
	else if (a == b)
		result = 0;
	else
		result = 1;

	return(result);
}

#endif /* USE_SPLAY_TREE */

/*****************************************************************************/

/* Allocate all the necessary resources to get going. */
static BOOL
setup(
	const TEXT *	program_name,
	const TEXT *	service,
	const TEXT *	workgroup,
	STRPTR			username,
	STRPTR			opt_password,
	BOOL			opt_change_username_case,
	BOOL			opt_change_password_case,
	const TEXT *	opt_clientname,
	const TEXT *	opt_servername,
	int				opt_cachesize,
	int				opt_max_transmit,
	int				opt_timeout,
	LONG *			opt_time_zone_offset,
	LONG *			opt_dst_offset,
	BOOL			opt_raw_smb,
	BOOL			opt_unicode,
	BOOL			opt_prefer_core_protocol,
	BOOL			opt_session_setup_delay_unicode,
	BOOL			opt_write_behind,
	int				opt_smb_request_write_threshold,
	int				opt_smb_request_read_threshold,
	BOOL			opt_scatter_gather,
	BOOL			opt_tcp_no_delay,
	int				opt_socket_receive_buffer_size,
	int				opt_socket_send_buffer_size,
	const TEXT *	device_name,
	const TEXT *	volume_name,
	BOOL			opt_add_volume,
	const TEXT *	translation_file)
{
	BOOL result = FALSE;
	struct DosList * dl;
	int error = 0;
	int smb_error_class = 0, smb_error = 0;
	const TEXT * actual_volume_name;
	int actual_volume_name_len;
	TEXT name[MAX_FILENAME_LEN+1];
	smba_connect_parameters_t par;
	BOOL device_exists = FALSE;
	int len,i;

	ENTER();

	PROFILE_OFF();

	NewList((struct List *)&FileList);
	NewList((struct List *)&LockList);

	#ifdef USE_SPLAY_TREE
	{
		/* File names may not be unique. */
		splay_tree_init(&FileNameTree, (splay_key_compare_t)compare_names);
		FileNameTree.st_allow_duplicates = TRUE;

		splay_tree_init(&FileAddressTree, compare_file_or_lock_by_address);

		/* Lock names may not be unique. */
		splay_tree_init(&LockNameTree, (splay_key_compare_t)compare_names);
		LockNameTree.st_allow_duplicates = TRUE;

		splay_tree_init(&LockAddressTree, compare_file_or_lock_by_address);
	}
	#endif /* USE_SPLAY_TREE */

	MemoryPool = CreatePool(MEMF_ANY|MEMF_PUBLIC, 4096, 4096);
	if(MemoryPool == NULL)
	{
		report_error("Could not create memory pool.");
		goto out;
	}

	LocaleBase = OpenLibrary("locale.library",38);

	#if defined(__amigaos4__)
	{
		if(LocaleBase != NULL)
		{
			ILocale = (struct LocaleIFace *)GetInterface(LocaleBase, "main", 1, 0);
			if(ILocale == NULL)
			{
				CloseLibrary(LocaleBase);
				LocaleBase = NULL;
			}
		}
	}
	#endif /* __amigaos4__ */

	/* We cache the default locale: the GMT offset value may change over time. */
	if(LocaleBase != NULL)
		Locale = OpenLocale(NULL);

	if(opt_time_zone_offset != NULL)
	{
		TimeZoneOffset			= -(*opt_time_zone_offset);
		OverrideLocaleTimeZone	= TRUE;

		SHOWVALUE(TimeZoneOffset);
	}
	else
	{
		if(Locale != NULL)
			SHOWVALUE(Locale->loc_GMTOffset);
	}

	if(opt_dst_offset != NULL)
	{
		DSTOffset = -60 * (*opt_dst_offset);

		SHOWVALUE(DSTOffset);
	}

	TimerPort = CreateMsgPort();
	if(TimerPort != NULL)
		TimerRequest = (struct timerequest *)CreateIORequest(TimerPort, sizeof(*TimerRequest));

	if(TimerRequest == NULL || OpenDevice(TIMERNAME,UNIT_VBLANK,(struct IORequest *)TimerRequest,0) != OK)
	{
		report_error("Could not open 'timer.device'.");
		goto out;
	}

	TimerBase = (struct Library *)TimerRequest->tr_node.io_Device;

	#if defined(__amigaos4__)
	{
		ASSERT(TimerBase != NULL);

		ITimer = (struct TimerIFace *)GetInterface(TimerBase, "main", 1, 0);
		if(ITimer == NULL)
		{
			report_error("Could not open 'timer.device'.");
			goto out;
		}
	}
	#endif /* __amigaos4__ */

	SocketBase = OpenLibrary("bsdsocket.library",3);

	#if defined(__amigaos4__)
	{
		if(SocketBase != NULL)
		{
			ISocket = (struct SocketIFace *)GetInterface(SocketBase, "main", 1, 0);
			if(ISocket == NULL)
			{
				CloseLibrary(SocketBase);
				SocketBase = NULL;
			}
		}
	}
	#endif /* __amigaos4__ */

	if(SocketBase == NULL)
	{
		report_error("Could not open 'bsdsocket.library' V3; TCP/IP stack not running?");
		goto out;
	}

	error = SocketBaseTags(
		SBTM_SETVAL(SBTC_ERRNOPTR(sizeof(errno))),	&errno,
		SBTM_SETVAL(SBTC_HERRNOLONGPTR),			&h_errno,
		SBTM_SETVAL(SBTC_LOGTAGPTR),				program_name,
		SBTM_SETVAL(SBTC_BREAKMASK),				SIGBREAKF_CTRL_C,
	TAG_END);

	if(error != OK)
	{
		report_error("Could not initialize 'bsdsocket.library' (%ld, %s).",error,posix_strerror(error));
		goto out;
	}

	/* Convert the user name into all-uppercase characters? */
	if(opt_change_username_case)
		string_toupper(username);

	/* Convert the password into all-uppercase characters? */
	if(opt_change_password_case)
		string_toupper(opt_password);

	/* Read the translation file, if possible. */
	if(translation_file != NULL)
	{
		STRPTR msg = NULL;
		BPTR file;

		error = OK;

		D(("using translation file '%s'",translation_file));

		file = Open(translation_file,MODE_OLDFILE);
		if(file != ZERO)
		{
			LONG num_bytes_read = 0;
			LONG n;

			n = Read(file,map_amiga_to_smb_name,256);
			if(n == 256)
			{
				num_bytes_read += n;

				n = Read(file,map_smb_to_amiga_name,256);
				if(n > 0)
					num_bytes_read += n;
			}

			if(n < 0)
			{
				msg = "Could not read translation file";

				error = IoErr();
			}
			else if (num_bytes_read < 512)
			{
				msg = "Translation file is too short";
			}

			Close(file);
		}
		else
		{
			msg = "Could not open translation file";
			error = IoErr();
		}

		if (msg == NULL)
		{
			TranslateNames = TRUE;
		}
		else if (error == OK)
		{
			report_error("%s '%s'.",msg,translation_file);
			goto out;
		}
		else
		{
			TEXT description[100];
			STRPTR s;

			Fault(error,NULL,description,sizeof(description));

			/* Drop the line feed - we don't need it. */
			s = strchr(description,'\n');
			if(s != NULL)
				(*s) = '\0';

			report_error("%s '%s' (%ld, %s).",msg,translation_file,error,description);
			goto out;
		}
	}

	memset(&par,0,sizeof(par));

	if(smba_start(
		service,
		workgroup,
		username,
		opt_password,
		opt_clientname,
		opt_servername,
		opt_cachesize,
		opt_max_transmit,
		opt_timeout,
		opt_raw_smb,
		opt_unicode,
		opt_prefer_core_protocol,
		CaseSensitive,
		opt_session_setup_delay_unicode,
		opt_write_behind,
		opt_smb_request_write_threshold,
		opt_smb_request_read_threshold,
		opt_scatter_gather,
		opt_tcp_no_delay,
		opt_socket_receive_buffer_size,
		opt_socket_send_buffer_size,
		&error,
		&smb_error_class,
		&smb_error,
		&par,
		&ServerData) < 0)
	{
		goto out;
	}

	FileSystemPort = CreateMsgPort();
	if(FileSystemPort == NULL)
	{
		report_error("Could not create filesystem port.");
		goto out;
	}

	/* If a device name was provided, check whether it is
	 * well-formed, and whether a device of that name
	 * already exists.
	 */
	if(device_name != NULL)
	{
		len = strlen(device_name);

		/* Lose the trailing ':' character, if any. */
		if(len > 0 && device_name[len-1] == ':')
			len--;

		if(NOT is_valid_device_name(device_name, len))
		{
			report_error("Device name '%s' cannot be used with AmigaDOS.",device_name);
			goto out;
		}

		memcpy(name,device_name,len);
		name[len] = '\0';

		dl = LockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		/* Does this device name already exist? Note that
		 * device names must be unique.
		 */
		if(FindDosEntry(dl,name,LDF_DEVICES) != NULL)
			device_exists = TRUE;
	}
	/* Otherwise pick a device name of the form SMBFS0..SMBFS99,
	 * which is not currently in use.
	 */
	else
	{
		dl = LockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		/* Try to find a unique device name out of 100 possible options. */
		for(i = 0 ; i < 100 ; i++)
		{
			LocalSNPrintf(name,sizeof(name),"SMBFS%ld",i);

			device_exists = (BOOL)(FindDosEntry(dl,name,LDF_DEVICES) != NULL);
			if(NOT device_exists)
			{
				device_name = name;
				break;
			}
		}
	}

	if(device_exists)
	{
		UnLockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		report_error("Device name '%s:' is already taken.",device_name);
		goto out;
	}

	/* Finally, create the device node. */
	DeviceNode = MakeDosEntry(name,DLT_DEVICE);
	if(DeviceNode == NULL)
	{
		UnLockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		report_error("Could not create device node.");
		goto out;
	}

	DeviceNode->dol_Task = FileSystemPort;

	/* If requested, add a volume name, using the service
	 * name as the default value.
	 */
	if(opt_add_volume && volume_name == NULL)
		volume_name = par.service;

	/* Examine the volume name; make sure that it is
	 * well-formed.
	 */
	if(volume_name == NULL)
		actual_volume_name = device_name;
	else
		actual_volume_name = volume_name;

	/* Ignore a trailing colon character. */
	actual_volume_name_len = strlen(actual_volume_name);
	if(actual_volume_name_len > 0 && actual_volume_name[actual_volume_name_len-1] == ':')
		actual_volume_name_len--;

	D(("actual volume name = '%s', length = %ld",actual_volume_name,actual_volume_name_len));

	if(NOT is_valid_device_name(actual_volume_name,actual_volume_name_len))
	{
		UnLockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		report_error("Volume name '%s' cannot be used with AmigaDOS.",actual_volume_name);
		goto out;
	}

	/* Now, finally, take care of the volume name. */
	memcpy(name,actual_volume_name,actual_volume_name_len);
	name[actual_volume_name_len] = '\0';

	VolumeNode = MakeDosEntry(name,DLT_VOLUME);
	if(VolumeNode == NULL)
	{
		UnLockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

		report_error("Could not create volume node.");
		goto out;
	}

	VolumeNode->dol_Task = FileSystemPort;
	DateStamp(&VolumeNode->dol_misc.dol_volume.dol_VolumeDate);

	/* Allow the file system to be identified by looking at the
	 * contents of the volume node. We put "SMB\0" into the
	 * dol_DiskType field. This was suggested by Chris Handley
	 * and Chris Young. Thank you very much!
	 */
	VolumeNode->dol_misc.dol_volume.dol_DiskType = ID_SMB_DISK;

	if(DeviceNode != NULL)
	{
		AddDosEntry(DeviceNode);

		DeviceNodeAdded = TRUE;
	}

	/* Note: We always need the volume node to make some file
	 *       system operations safe (e.g. Lock()), but we may
	 *       not always need to make it visible.
	 */
	if(volume_name != NULL && VolumeNode != NULL)
	{
		AddDosEntry(VolumeNode);

		VolumeNodeAdded = TRUE;
	}

	/* And that concludes the mounting operation. */
	UnLockDosList(LDF_WRITE|LDF_VOLUMES|LDF_DEVICES);

	/* Tell Workbench and friends to update their volume lists. */
	if(VolumeNodeAdded)
		send_disk_change_notification(IECLASS_DISKINSERTED);

	if(Cli() != NULL)
		SetProgramName(NewProgramName);

	result = TRUE;

 out:

	PROFILE_ON();

	RETURN(result);
	return(result);
}

/****************************************************************************/

static void
add_file_node(struct FileNode * fn)
{
	ASSERT( fn != NULL );

	AddTail((struct List *)&FileList,(struct Node *)fn);

	#ifdef USE_SPLAY_TREE
	{
		fn->fn_SplayNameNode.sn_key = (splay_key_t)fn->fn_FullName;
		fn->fn_SplayNameNode.sn_userdata = fn;
		splay_tree_add(&FileNameTree, &fn->fn_SplayNameNode);

		fn->fn_SplayAddressNode.sn_key = (splay_key_t)fn;
		fn->fn_SplayAddressNode.sn_userdata = fn;
		splay_tree_add(&FileAddressTree, &fn->fn_SplayAddressNode);
	}
	#endif /* USE_SPLAY_TREE */
}

/****************************************************************************/

static void
remove_file_node(struct FileNode * fn)
{
	ASSERT( fn != NULL );

	Remove((struct Node *)fn);

	#ifdef USE_SPLAY_TREE
	{
		APTR found;

		found = splay_tree_remove(&FileNameTree, &fn->fn_SplayNameNode, (splay_key_t)fn->fn_FullName);

		D(("file name node removal %s", found != NULL ? "succeeded" : "failed"));

		found = splay_tree_remove(&FileAddressTree, NULL, (splay_key_t)fn);

		D(("file address node removal %s", found != NULL ? "succeeded" : "failed"));
	}
	#endif /* USE_SPLAY_TREE */
}

/****************************************************************************/

static void
add_lock_node(struct LockNode * ln)
{
	ASSERT( ln != NULL );

	AddTail((struct List *)&LockList,(struct Node *)ln);

	#ifdef USE_SPLAY_TREE
	{
		ln->ln_SplayNameNode.sn_key = (splay_key_t)ln->ln_FullName;
		ln->ln_SplayNameNode.sn_userdata = ln;
		splay_tree_add(&LockNameTree, &ln->ln_SplayNameNode);

		ln->ln_SplayAddressNode.sn_key = (splay_key_t)ln;
		ln->ln_SplayAddressNode.sn_userdata = ln;
		splay_tree_add(&LockAddressTree, &ln->ln_SplayAddressNode);
	}
	#endif /* USE_SPLAY_TREE */
}

/****************************************************************************/

static void
remove_lock_node(struct LockNode * ln)
{
	ASSERT( ln != NULL );

	Remove((struct Node *)ln);

	#ifdef USE_SPLAY_TREE
	{
		APTR found;

		found = splay_tree_remove(&LockNameTree, &ln->ln_SplayNameNode, ln->ln_SplayNameNode.sn_key);

		D(("lock name node removal %s", found != NULL ? "succeeded" : "failed"));

		found = splay_tree_remove(&LockAddressTree, NULL, (splay_key_t)ln);

		D(("lock address node removal %s", found != NULL ? "succeeded" : "failed"));
	}
	#endif /* USE_SPLAY_TREE */

	/* This will make the lock_is_invalid() tests return
	 * TRUE, which should make it easier to detect
	 * files which have been closed already, should the
	 * file system receive them.
	 */
	ln->ln_FileLock.fl_Volume = (BPTR)NULL;
	ln->ln_FileLock.fl_Key = 0;
	ln->ln_File = NULL;
	ln->ln_Magic = 0;
}

/****************************************************************************/

/* Truncate an file size or position which cannot be represented by a
 * single 32 bit integer and substitute it with something vaguely more
 * sensible (which probably isn't so sensible in the first place, but
 * we keep trying).
 */
static ULONG
truncate_64_bit_position(const QUAD * position_quad)
{
	ULONG result;

	if(position_quad->High == 0)
		result = position_quad->Low;
	else
		result = 0xFFFFFFFFUL;

	return(result);
}

/****************************************************************************/

#if DEBUG

/* Create a form of the given file/directory name which shows unprintable
 * characters through the use of 'C' style escape sequences. Returns a
 * pointer to a local static buffer which contains the escaped string.
 * If the escape form of the name is too long to fit into the buffer,
 * the text " [...]" will be appended to the contents of the buffer, to
 * indicate that the name was truncated.
 */
TEXT *
escape_name(const TEXT * name)
{
	static const TEXT truncated_suffix[] = " [...]";
	static TEXT buffer[4 * 256 + sizeof(truncated_suffix)];

	const int buffer_size = (int)sizeof(buffer) - sizeof(truncated_suffix);
	BOOL truncated = FALSE;
	TEXT hex_code[6];
	TEXT * str;
	int len;
	TEXT c;

	if(name == NULL)
		name = "***NULL POINTER***";

	len = 0;

	while((c = (*name++)) != '\0')
	{
		if (c < ' ')
		{
			int l = 2;

			switch(c)
			{
				case '\a':

					str = "\\a";
					break;

				case '\b':

					str = "\\b";
					break;

				case '\f':

					str = "\\f";
					break;

				case '\n':

					str = "\\n";
					break;

				case '\r':

					str = "\\r";
					break;

				case '\t':

					str = "\\t";
					break;

				case '\v':

					str = "\\v";
					break;

				default:

					LocalSNPrintf(hex_code,sizeof(hex_code),"\\x%02lx",c);
					str = hex_code;

					l = 4;
					break;
			}

			if(len + l >= buffer_size)
			{
				truncated = TRUE;
				break;
			}

			memcpy(&buffer[len],str,l);
			len += l;
		}
		else if (127 <= c && c <= 160)
		{
			if(len + 4 >= buffer_size)
			{
				truncated = TRUE;
				break;
			}

			LocalSNPrintf(hex_code,sizeof(hex_code),"\\x%02lx",c);

			memcpy(&buffer[len],hex_code,4);
			len += 4;
		}
		else if (c == '\\')
		{
			if(len + 2 >= buffer_size)
			{
				truncated = TRUE;
				break;
			}

			buffer[len++] = c;
			buffer[len++] = c;
		}
		else
		{
			if(len + 1 >= buffer_size)
			{
				truncated = TRUE;
				break;
			}

			buffer[len++] = c;
		}
	}

	if(truncated)
	{
		memcpy(&buffer[len],truncated_suffix,sizeof(truncated_suffix)-1);
		len += sizeof(truncated_suffix)-1;
	}

	ASSERT( len < (int)sizeof(buffer) );

	buffer[len] = '\0';

	return(buffer);
}

#endif /* DEBUG */

/****************************************************************************/

/* Convert a BCPL string into a standard NUL-terminated 'C' string.
 * Note that these must be different strings which must not
 * overlap!
 */
static int
convert_from_bcpl_to_c_string(STRPTR cstring,int cstring_size,const void * bstring)
{
	const TEXT * from = bstring;
	int len;

	ASSERT( cstring_size > 0 );

	len = from[0];
	if(len > cstring_size-1)
		len = cstring_size-1;

	if(len > 0)
		memcpy(cstring,&from[1],len);

	if(cstring_size > 0)
	{
		ASSERT( len >= 0 );

		cstring[len] = '\0';
	}

	return(len);
}

/* Convert a NUL-terminated 'C' string into a BCPL string. */
static void
convert_from_c_to_bcpl_string(void * bstring,int bstring_size,const TEXT * cstring,int len)
{
	TEXT * to = bstring;

	ASSERT( bstring_size > 0 );

	if(bstring_size > 0)
	{
		if(bstring_size > MAX_FILENAME_LEN+1)
			bstring_size = MAX_FILENAME_LEN+1;

		if(len > bstring_size-1)
			len = bstring_size-1;

		(*to++) = len;
		memcpy(to,cstring,len);
	}
}

/****************************************************************************/

/* Allocate memory for storing a copy of a string with given
 * length. Sufficient memory will be allocated for proper
 * NUL-termination.
 */
static TEXT *
allocate_and_copy_string(const TEXT * original_str, int len)
{
	TEXT * copied_str;

	ASSERT( original_str != NULL && len >= 0 );

	copied_str = allocate_memory(len + 1);
	if(copied_str != NULL)
	{
		if(len > 0)
			memcpy(copied_str, original_str, len);

		copied_str[len] = '\0';
	}

	return(copied_str);
}

/****************************************************************************/

/* Return the next part (segment) of an AmigaDOS path name, which
 * is either ":" (= go to root directory), "/" (= go to parent
 * directory) or the name of a file or directory.
 *
 * The segment name will be copied into the provided buffer, and
 * just to be sure, the total length of the segment name will be
 * provided separately. If the segment name was truncated you
 * can find out by comparing the segment buffer size with the
 * segment length indicated.
 */
static int
get_next_path_segment(
	const TEXT *	path,
	int				path_len,
	int				offset,
	TEXT *			segment,
	int				segment_size,
	int *			segment_len_ptr)
{
	ASSERT( path_len >= 0 );
	ASSERT( path != NULL || path_len == 0 );
	ASSERT( segment_size >= 0 );
	ASSERT( segment != NULL || segment_size == 0 );
	ASSERT( segment_len_ptr != NULL );

	/* No segment processed yet. */
	(*segment_len_ptr) = 0;

	/* Is there still something to process? */
	if(offset < path_len)
	{
		TEXT c;

		c = path[offset];

		/* If there's a leading ":" or "/" character,
		 * it means that this is not a path delimiter
		 * but a control character instead. We return
		 * that control character as is.
		 *
		 * Note that the ":" only has meaning if it is
		 * the very first character of the path string.
		 */
		if((c == ':' && offset == 0) || c == '/')
		{
			(*segment_len_ptr) = 1;

			/* Return this as the next segment. */
			if(segment_size > 0)
			{
				/* This is for the terminating NUL byte. */
				segment_size--;

				/* Can we store the single control character? */
				if(segment_size > 0)
					(*segment++) = c;

				(*segment) = '\0';
			}

			offset += 1;
		}
		/* Otherwise check if there is a directory
		 * or file name which needs to be processed.
		 */
		else
		{
			int i;

			for(i = offset ; i <= path_len ; i++)
			{
				/* We search for the end of the segment,
				 * which is either the end of the path string
				 * or where we found another path delimiter
				 * character.
				 */
				if(i == path_len || path[i] == '/')
				{
					int len;

					len = i - offset;

					ASSERT( len > 0 );

					(*segment_len_ptr) = len;

					/* Return this as the next segment. */
					if(segment_size > 0)
					{
						/* This is for the terminating NUL byte. */
						segment_size--;

						/* Can we store the path, or at least a part of it? */
						if(segment_size > 0)
						{
							/* Don't copy more characters than will fit. */
							if(segment_size < len)
								len = segment_size;

							memmove(segment,&path[offset],len);
							segment += len;
						}

						(*segment) = '\0';
					}

					offset = i+1;
					break;
				}
			}
		}
	}

	return(offset);
}

/****************************************************************************/

/* Build the fully qualified name of a file or directory in reference
 * to the name of the parent directory. This takes care of all the
 * special cases, such as the root directory. The result will be converted
 * to be in a form suitable for use with the SMB file sharing service.
 *
 * Note that the parent directory name uses SMB path name separator
 * characters ("\"), but the path name to be added ("name") uses the
 * AmigaDOS path name separator characters ("/").
 */
static int
build_full_path_name(
	const TEXT *	parent_name,
	const TEXT *	name,
	int				name_len,
	STRPTR *		result_ptr)
{
	int error = OK;
	int parent_name_len;
	STRPTR buffer;
	STRPTR to;
	int size;
	int len;

	ENTER();

	if(parent_name == NULL)
		SHOWMSG("parent name = NULL");
	else
		D(("parent name = '%s'",escape_name(parent_name)));

	if(name == NULL)
		SHOWMSG("name = NULL");
	else
		D(("name = '%s'",escape_name(name)));

	(*result_ptr) = NULL;

	if(name == NULL)
		name_len = 0;

	/* A NULL parent name stands in for the ZERO lock,
	 * which refers to the root directory of the volume.
	 */
	if(parent_name == NULL)
		parent_name = SMB_ROOT_DIR_NAME;

	parent_name_len = strlen(parent_name);

	size = parent_name_len + 1;

	/* The combined parent and path names may end up being shorter
	 * than what we allocate memory for, but we'd rather play it
	 * safe...
	 */
	if(name_len > 0)
	{
		BOOL name_changed = FALSE;
		TEXT c;
		int i;

		/* Remove a trailing '/' since it has no meaning and
		 * might just lead to trouble during parsing.
		 */
		if(name[name_len - 1] == '/' && name_len > 1)
		{
			if(name[name_len - 2] != '/')
			{
				name_len--;

				name_changed = TRUE;
			}
		}

		/* Remove a device, volume or assignment name from the path name.
		 * If necessary, the path following the ':' character will be
		 * retained.
		 *
		 * This process is necessary because the dos.library packet interface
		 * will usually provide a FileLock along with the complete path name
		 * of the file or drawer which must be interpreted relative to the
		 * FileLock.
		 *
		 * In the simple case this would be, for example, a FileLock on the
		 * "Workbench:Tools" directory and a path of name "Calculator". But
		 * it is also possible for the path to contain a volume name or
		 * assignment, e.g. a FileLock on "SYS:C" and a path name of "C:Dir".
		 * In the latter case the FileLock already refers to the correct
		 * parent directory and the device, volume or assignment must be
		 * removed from the path, which in this case would replace "C:Dir"
		 * with "Dir".
		 */
		for(i = 0 ; i < name_len ; i++)
		{
			c = name[i];

			/* A path delimiter cannot be part of a volume, device or
			 * assignment name, so we don't bother checking the remainder
			 * of the path.
			 */
			if(c == '/')
				break;

			/* This is either a control character (the path name is
			 * actually ":") or indicates the end of a volume, device
			 * or assignment name.
			 */
			if(c == ':')
			{
				/* Remove the volume, device or assignment name if
				 * there is one.
				 */
				if(i > 0)
				{
					name		+= i+1;
					name_len	-= i+1;

					name_changed = TRUE;
				}

				break;
			}
		}

		#if DEBUG
		{
			if(name_changed)
			{
				TEXT printable_name[MAX_FILENAME_LEN+1];
				int l;

				l = name_len;
				if(l >= (int)sizeof(printable_name))
					l = sizeof(printable_name)-1;

				memmove(printable_name, name, l);
				printable_name[l] = '\0';

				D(("name changed to '%s'",escape_name(printable_name)));
			}
		}
		#endif /* DEBUG */

		size += 1 + name_len;
	}

	buffer = allocate_memory(size);
	if(buffer == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	to = buffer;

	memcpy(to,parent_name,parent_name_len);
	to += parent_name_len;

	ASSERT( buffer <= to );

	len = (int)(to - buffer);

	/* Add the path name to the full path, if available. */
	if(name_len > 0)
	{
		TEXT segment[MAX_FILENAME_LEN+1];
		int segment_len;
		int offset, next_offset;

		/* The parent directory name must be an absolute path. */
		ASSERT( strncmp(buffer,SMB_ROOT_DIR_NAME,1) == SAME );

		for(offset = 0 ; offset < name_len ; offset = next_offset)
		{
			next_offset = get_next_path_segment(name,name_len,offset,segment,sizeof(segment),&segment_len);

			D(("segment = '%s', len=%ld, offset=%ld -> %ld", segment, segment_len, offset, next_offset));

			/* Segment buffer overflow or something even weirder? */
			if(segment_len == 0 || segment_len > (int)sizeof(segment))
			{
				if(segment_len == 0)
					D(("segment path processing failed"));
				else
					D(("segment length %ld overflows buffer", segment_len));

				error = ERROR_BUFFER_OVERFLOW;
				goto out;
			}

			/* Move up to the root directory? Note that the ":" only has
			 * this particular meaning if it is found as the first
			 * character of the name.
			 */
			if (offset == 0 && strcmp(segment,":") == SAME)
			{
				to = &buffer[1];
				len = 1;
			}
			/* Move up to the parent directory? */
			else if (strcmp(segment,"/") == SAME)
			{
				/* Unless we are already at the root directory
				 * level, try to find the parent of the current
				 * path by looking for the last path separator.
				 */
				if(len > 1)
				{
					int i;

					ASSERT( buffer[0] == SMB_PATH_SEPARATOR );

					for(i = len-1 ; i >= 0 ; i--)
					{
						if(buffer[i] == SMB_PATH_SEPARATOR)
						{
							/* Don't move above the root, e.g "\foo" must become "\". */
							if(i == 0)
							{
								to = &buffer[1];
								len = 1;
							}
							/* Remove the final part of the path name, including the
							 * path delimiter, e.g. "\foo\bar" must become "\foo".
							 */
							else
							{
								to = &buffer[i];
								len = i;
							}

							break;
						}
					}
				}
				/* Can't go any further. */
				else
				{
					SHOWMSG("can't go any further up in the path");

					error = ERROR_OBJECT_NOT_FOUND;
					goto out;
				}
			}
			/* Add the file/drawer name to the full path. */
			else
			{
				/* Is the current path representing the root directory? */
				if(len == 1)
				{
					/* So there better be enough room to add this path. */
					ASSERT( len + segment_len + 1 <= size );
				}
				else
				{
					/* We need to add a path delimiter. */
					ASSERT( len + 1 + segment_len + 1 <= size );

					(*to++) = SMB_PATH_SEPARATOR;
					len++;
				}

				memmove(to,segment,segment_len);
				to += segment_len;

				len += segment_len;
			}

			#if DEBUG
			{
				buffer[len] = '\0';

				D(("full path name = '%s', length = %ld", escape_name(buffer), len));
			}
			#endif /* DEBUG */
		}
	}

	ASSERT( len < size );

	buffer[len] = '\0';

	D(("full path name = '%s'",escape_name(buffer)));
	SHOWVALUE(size);
	SHOWVALUE(len);

	(*result_ptr) = buffer;
	buffer = NULL;

 out:

	free_memory(buffer);

	RETURN(error);
	return(error);
}

/****************************************************************************/

/* Break up an SMB path name into two parts, this being the directory part
 * and a base part. For example, in "\foo\bar\baz" the directory part would
 * be "\foo\bar" and the base part would be "baz".
 *
 * Because breaking up the path name may require adding a NUL byte to
 * separate the directory and base parts, buffer memory will be allocated to
 * hold the path name.
 *
 * Pointers to the directory and base parts will be provided by filling in the
 * dir_part_ptr and base_part_ptr pointers, unless these are NULL. Note that
 * the strings are read-only.
 *
 * This function will return an error if memory allocation failed or if the
 * path name provided cannot be split.
 *
 * Make sure to release the memory allocated which the temp_ptr will point to
 * when you no longer need it.
 */
static int
split_path_name(
	const TEXT *	path,
	int				path_len,
	STRPTR *		temp_ptr,
	STRPTR *		dir_part_ptr,
	STRPTR *		base_part_ptr)
{
	STRPTR dir_part = NULL;
	STRPTR base_part = NULL;
	int error = OK;
	STRPTR temp;
	int i;

	ASSERT( path != NULL && path_len >= 0 && temp_ptr != NULL );

	(*temp_ptr) = NULL;

	if(dir_part_ptr != NULL)
		(*dir_part_ptr) = NULL;

	if(base_part_ptr != NULL)
		(*base_part_ptr) = NULL;

	/* Make a copy of the path string. */
	temp = allocate_and_copy_string(path, path_len);

	/* Find the last '\' character which separates
	 * the directory part from the base part.
	 */
	for(i = path_len-1 ; i >= 0 ; i--)
	{
		if(temp[i] == SMB_PATH_SEPARATOR)
		{
			/* Is this the root directory? */
			if(i == 0)
			{
				/* We return this constant value as the
				 * directory part (root directory).
				 */
				dir_part = SMB_ROOT_DIR_NAME;

				/* If possible, return what follows the root
				 * directory as the base part.
				 */
				if(path_len > 1)
					base_part = &temp[i+1];
			}
			else
			{
				/* Chop off the directory part. */
				dir_part = temp;
				temp[i] = '\0';

				if(i+1 < path_len)
					base_part = &temp[i+1];
			}

			break;
		}
	}

	/* We have to have a directory part and a base part. */
	if(dir_part == NULL || base_part == NULL)
	{
		error = ERROR_INVALID_COMPONENT_NAME;
		goto out;
	}

	/* Don't forget to free this when it is no longer needed. */
	(*temp_ptr) = temp;
	temp = NULL;

	if(dir_part_ptr != NULL)
		(*dir_part_ptr) = dir_part;

	if(base_part_ptr != NULL)
		(*base_part_ptr) = base_part;

 out:

	free_memory(temp);

	return(error);
}

/****************************************************************************/

/* Return a pointer to the base part of an SMB path name. For example,
 * in "\foo\bar\baz" the base part would be "baz", and in "foo" the
 * base part (in the absence of a directory part) would be identical
 * to the path name "foo".
 *
 * Note that this function requires the path name to consist of a
 * directory and a base part, and the base part must not be empty,
 * e.g. "foo\" is not supported.
 */
static const TEXT *
get_base_name(const TEXT * path_name,int path_name_len)
{
	const TEXT * result = path_name;

	if(path_name_len > 1)
	{
		int i;

		for(i = path_name_len-1 ; i >= 0 ; i--)
		{
			if(path_name[i] == SMB_PATH_SEPARATOR)
			{
				ASSERT( i+1 < path_name_len );

				result = &path_name[i+1];
				break;
			}
		}
	}

	return(result);
}

/****************************************************************************/

/* Find the parent directory of a file or directory. This strips off the
 * last part of the name, e.g. translating "\foo" into "\" and "\foo\bar"
 * into "\foo". There is no parent for the root directory ("\"), which
 * is signalled by setting the error code returned to ERROR_OBJECT_NOT_FOUND.
 */
static int
get_parent_dir_name(const TEXT * name,int name_len,STRPTR * parent_name_ptr)
{
	STRPTR parent_name = NULL;
	int error;
	int i;

	ENTER();

	ASSERT( name != NULL && name_len >= 0 && parent_name_ptr != NULL );

	(*parent_name_ptr) = NULL;

	D(("finding parent directory of '%s'",escape_name(name)));

	if(name_len == 0)
	{
		SHOWMSG("no parent directory found");

		/* The root directory has no parent. */
		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	/* Drop any trailing '\' character. */
	if(name_len > 1 && name[name_len-1] == SMB_PATH_SEPARATOR)
		name_len--;

	if(name_len == 1 && name[0] == SMB_PATH_SEPARATOR)
	{
		SHOWMSG("no parent directory found");

		/* The root directory has no parent. */
		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	/* Remove the last part of the path. */
	for(i = name_len - 1 ; i >= 0 ; i--)
	{
		if(name[i] == SMB_PATH_SEPARATOR)
		{
			/* This translates "\foo" into "\", and
			 * "\foo\bar" into "\foo".
			 */
			if(i == 0)
				name_len = 1;
			else
				name_len = i;

			break;
		}
	}

	parent_name = allocate_and_copy_string(name, name_len);
	if(parent_name == NULL)
	{
		SHOWMSG("not enough memory");

		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	D(("parent directory = '%s'",escape_name(parent_name)));

	(*parent_name_ptr) = parent_name;
	parent_name = NULL;

	error = OK;

 out:

	free_memory(parent_name);

	RETURN(error);
	return(error);
}

/****************************************************************************/

/* Translate an Amiga file name into an encoded form, such as
 * through a code page translation table. The file name provided will
 * be modified in place and may become longer than it already is.
 *
 * Note that if code page based file name translation is disabled
 * then this function will do nothing and leave the file name
 * unchanged.
 *
 * This function returns an AmigaDOS error code if the translation
 * cannot be performed and 0 otherwise.
 */
static int
translate_amiga_name_to_smb_name(TEXT * name, int name_len, int name_size)
{
	int error = ERROR_INVALID_COMPONENT_NAME;

	ASSERT( name != NULL && name_len < name_size );

	/* Translate the Amiga file name using a translation table? */
	if(TranslateNames)
	{
		const TEXT * map = map_amiga_to_smb_name;
		TEXT c;
		int i;

		for(i = 0 ; i < name_len ; i++)
		{
			c = map[name[i]];

			/* The NUL means that the respective mapping cannot
			 * represent the desired character.
			 */
			if(c == '\0')
				goto out;

			name[i] = c;
		}
	}

	error = OK;

 out:

	return(error);
}

/****************************************************************************/

/* Translate an SMB file name in encoded form, such as
 * through a code page translation table, into a form suitable
 * for use with AmigaDOS. The file name provided will be modified
 * in place and may become longer than it already is.
 *
 * This function returns an AmigaDOS error code if the translation
 * cannot be performed and 0 otherwise.
 */
static int
translate_smb_name_to_amiga_name(TEXT * name, int name_len, int name_size)
{
	int error = ERROR_INVALID_COMPONENT_NAME;

	ASSERT( name != NULL && name_len < name_size );

	/* Translate the name to Amiga format using a mapping table. */
	if(TranslateNames)
	{
		const TEXT * map = map_smb_to_amiga_name;
		TEXT c;
		int i;

		for(i = 0 ; i < name_len ; i++)
		{
			c = map[name[i]];

			/* The NUL means that the respective mapping cannot
			 * represent the desired character.
			 */
			if(c == '\0')
				goto out;

			name[i] = c;
		}
	}

	error = OK;

 out:

	return(error);
}

/****************************************************************************/

/* Restart directory scanning for all locks which share
 * the parent directory of a directory or file which was
 * just deleted.
 *
 * Because restarting interferes with the default
 * procedure for deleting all the entries of a directory,
 * we do not restart scanning on directories which the
 * same process is currently scanning and issuing deletion
 * commands for.
 */
static void
restart_directory_scanning(const struct MsgPort * user,const TEXT * parent_dir_name)
{
	struct LockNode * ln;
	struct splay_node * sn;

	ENTER();

	SHOWSTRING(parent_dir_name);

	#ifndef USE_SPLAY_TREE
	{
		for(ln = (struct LockNode *)LockList.mlh_Head ;
		    ln->ln_MinNode.mln_Succ != NULL ;
		    ln = (struct LockNode *)ln->ln_MinNode.mln_Succ)
		{
			/* Try not to self-disrupt directory scanning while
			 * deleting the contents of the directory.
			 */
			if(ln->ln_LastUser == user)
				continue;

			if(compare_names(parent_dir_name,ln->ln_FullName) == SAME)
			{
				D(("restart scanning for '%s'", escape_name(ln->ln_FullName)));

				ln->ln_RestartExamine = TRUE;
			}
		}
	}
	#else
	{
		/* Find all the locks which share the same directory name. */
		sn = splay_tree_find(&LockNameTree, (splay_key_t)parent_dir_name);
		if(sn != NULL)
		{
			/* Check each lock in turn, restarting the directory
			 * scanning process unless the same program which
			 * requires the restart is the one currently
			 * doing the scanning.
			 */
			for((void)NULL ; sn != NULL ; sn = sn->sn_next)
			{
				ln = sn->sn_userdata;

				if(ln->ln_LastUser != user)
				{
					D(("restart scanning for '%s'", escape_name(ln->ln_FullName)));

					ln->ln_RestartExamine = TRUE;
				}
			}
		}
	}
	#endif /* USE_SPLAY_TREE */

	LEAVE();
}

/****************************************************************************/

/* Check if a file lock was not created by this file system
 * through CreateDir(), Lock(), ParentDir(), ParentOfFH(),
 * DupLock() or DupLockFromFH(). Returns TRUE if this is case,
 * FALSE otherwise.
 *
 * If this function returns FALSE, then the file lock has a
 * valid LockNode attached.
 *
 * Note that the ZERO lock is always rejected as invalid
 * by this function.
 */
static BOOL
lock_is_invalid(const struct FileLock * lock,int * error_ptr)
{
	int error = ERROR_INVALID_LOCK;
	const struct LockNode * ln;
	BOOL is_invalid = TRUE;

	SHOWPOINTER(lock);

	/* The ZERO lock is considered invalid. */
	if(lock == NULL)
	{
		SHOWMSG("ZERO lock not permitted");
		goto out;
	}

	/* The lock has to be associated with this
	 * file system's volume node.
	 */
	if(lock->fl_Volume != MKBADDR(VolumeNode))
	{
		SHOWMSG("volume node does not match");

		error = ERROR_NO_DISK;
		goto out;
	}

	/* We need a valid lock node to be associated
	 * with the file lock.
	 */
	ln = (struct LockNode *)lock->fl_Key;

	if(ln == NULL || lock != &ln->ln_FileLock || ln->ln_Magic != ID_SMB_DISK)
	{
		SHOWMSG("lock doesn't look right");
		goto out;
	}

	is_invalid = FALSE;

	error = OK;

 out:

	if(error_ptr != NULL)
		(*error_ptr) = error;

	return(is_invalid);
}

/****************************************************************************/

/* Check if a file node was not created by this file system
 * through Open() or OpenFromLock(). Returns TRUE if this is case,
 * FALSE otherwise.
 */
static BOOL
file_is_invalid(const struct FileNode * fn,int * error_ptr)
{
	int error = ERROR_INVALID_LOCK;
	BOOL is_invalid = TRUE;

	SHOWPOINTER(fn);

	if(fn == NULL)
	{
		SHOWMSG("no file node found");
		goto out;
	}

	/* The file has to be associated with this
	 * file system's volume node.
	 */
	if(fn->fn_Volume != VolumeNode)
	{
		SHOWMSG("volume node does not match");

		error = ERROR_NO_DISK;
		goto out;
	}

	if(fn->fn_Magic != ID_SMB_DISK)
	{
		SHOWMSG("file doesn't look right");
		goto out;
	}

	is_invalid = FALSE;

	error = OK;

 out:

	if(error_ptr != NULL)
		(*error_ptr) = error;

	return(is_invalid);
}

/****************************************************************************/

/* Try to obtain the path name stored in a FileLock which
 * a file or directory name is associated with. The parent
 * FileLock can be NULL, which is interpreted as being a
 * 'ZERO lock' that stands in for the root directory of the
 * volume.
 */
static BOOL
get_parent_name(
	const struct FileLock *	parent,
	const struct MsgPort *	user,
	STRPTR *				parent_name_ptr,
	int *					error_ptr)
{
	BOOL success = FALSE;
	STRPTR name;

	ASSERT( error_ptr != NULL );

	SHOWPOINTER(parent);

	if(parent != NULL)
	{
		struct LockNode * ln;

		if(lock_is_invalid(parent, error_ptr))
			goto out;

		ln = (struct LockNode *)parent->fl_Key;

		D(("parent lock on '%s'", escape_name(ln->ln_FullName)));

		ln->ln_LastUser = user;

		name = ln->ln_FullName;
	}
	else
	{
		SHOWMSG("parent lock on ':' (ZERO lock)");

		name = NULL;
	}

	if(parent_name_ptr != NULL)
		(*parent_name_ptr) = name;

	success = TRUE;

 out:

	return(success);
}

/****************************************************************************/

static BPTR
Action_Parent(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	LONG *					error_ptr)
{
	BPTR result = ZERO;
	STRPTR full_name = NULL;
	struct LockNode * parent_ln;
	struct LockNode * ln = NULL;
	int error;

	ENTER();

	SHOWPOINTER(parent);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* There are two kinds of locks which need to be dealt
	 * with. The first kind is the ZERO lock (= NULL), and
	 * the other is a pointer to a FileLock.
	 *
	 * The ZERO lock's parent is the ZERO lock. Note that
	 * this is not the same thing as trying to obtain a
	 * lock on the "/" directory, relative to the root
	 * directory (which must fail with the error code
	 * ERROR_OBJECT_NOT_FOUND set).
	 */
	if(parent != NULL)
	{
		if(lock_is_invalid(parent,&error))
			goto out;

		parent_ln = (struct LockNode *)parent->fl_Key;

		D(("parent lock on '%s'", escape_name(parent_ln->ln_FullName)));

		parent_ln->ln_LastUser = user;

		error = get_parent_dir_name(parent_ln->ln_FullName,strlen(parent_ln->ln_FullName),&full_name);
		if(error != OK)
		{
			/* Check if we ended up having to return the parent of
			 * the root directory. This is indicated by the
			 * error code ERROR_OBJECT_NOT_FOUND. The parent directory
			 * of the root directory is the ZERO lock.
			 */
			if(error != ERROR_OBJECT_NOT_FOUND)
				goto out;

			SHOWMSG("returning ZERO lock");
		}
		else
		{
			ln = allocate_lock_node(SHARED_LOCK,full_name,user);
			if(ln == NULL)
			{
				error = ERROR_NO_FREE_STORE;
				goto out;
			}

			D(("full_name = '%s'",escape_name(full_name)));

			if(smba_open(ServerData,full_name,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
			{
				error = map_errno_to_ioerr(error);
				goto out;
			}

			add_lock_node(ln);

			result = MKBADDR(&ln->ln_FileLock);
			SHOWPOINTER(&ln->ln_FileLock);

			full_name = NULL;
			ln = NULL;
		}
	}
	else
	{
		SHOWMSG("parent lock on ':' (ZERO lock)");

		SHOWMSG("returning ZERO lock");
	}

	error = OK;

 out:

	free_memory(full_name);
	free_memory(ln);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_DeleteObject(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	const void *			bcpl_name,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR full_name = NULL;
	smba_file_t * file = NULL;
	STRPTR parent_name;
	STRPTR full_parent_name = NULL;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	smba_stat_t st;
	int error;

	ENTER();

	D(("name = '%b'",MKBADDR(bcpl_name)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	/* Name string, as given in the DOS packet, is in
	 * BCPL format and needs to be converted into
	 * 'C' format.
	 */
	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to delete the root directory, are you kidding? */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot delete the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	/* Is there a file handle or file lock attached to this
	 * object? If so, we'll exit right away.
	 */
	error = check_access_mode_collision(full_name,EXCLUSIVE_LOCK);
	if(error != OK)
	{
		D(("there is still a lock or file attached to '%s'", full_name));
		goto out;
	}

	/* We need to find this file's parent directory, so that
	 * in case the directory contents are currently being
	 * examined, that process is restarted.
	 */
	error = get_parent_dir_name(full_name,strlen(full_name),&full_parent_name);
	if(error != OK)
		goto out;

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_read_only,open_dont_truncate,&file,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	if(smba_getattr(file,&st,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	smba_close(ServerData,file);
	file = NULL;

	if(st.is_dir)
	{
		SHOWMSG("removing a directory");

		if(smba_rmdir(ServerData,full_name,&error) < 0)
		{
			int translated_error;

			if(error == error_check_smb_error)
				translated_error = smb_errno(((struct smb_server *)ServerData)->rcls,((struct smb_server *)ServerData)->err);
			else
				translated_error = error;

			D(("that didn't work (error=%ld)", translated_error));

			/* This is a little bit difficult to justify since
			 * the error code may indicate a different cause,
			 * but in practice 'EACCES' seems to be returned
			 * if the directory to remove is not empty.
			 *
			 * Except when it isn't: the CIFS documentation
			 * mentions that ERRDOS/ERRnoaccess can mean
			 * "access denied", "directory is in use" or
			 * "directory is not empty". All of these may
			 * map to either EACCESS or EPERM (we don't use
			 * the third alternative ENOENT).
			 */
			if(translated_error == EACCES || translated_error == EPERM)
			{
				SHOWMSG("that directory might not be empty");

				error = ERROR_DIRECTORY_NOT_EMPTY;
			}
			else
			{
				SHOWMSG("could be some other problem");

				error = map_errno_to_ioerr(error);
			}

			goto out;
		}
	}
	else
	{
		SHOWMSG("removing a file");

		if(smba_remove(ServerData,full_name,&error) < 0)
		{
			SHOWVALUE(error);

			error = map_errno_to_ioerr(error);
			goto out;
		}
	}

	/* Restart directory scanning for all locks which share
	 * the parent directory of the object just deleted.
	 */
	restart_directory_scanning(user, full_parent_name);

	SHOWMSG("done.");

	result = DOSTRUE;
	error = OK;

 out:

	if(file != NULL)
		smba_close(ServerData,file);

	free_memory(full_name);
	free_memory(full_parent_name);

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_DELETE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static BPTR
Action_CreateDir(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	const void * 			bcpl_name,
	LONG *					error_ptr)
{
	BPTR result = ZERO;
	STRPTR full_name = NULL;
	struct LockNode * ln = NULL;
	STRPTR parent_name;
	smba_file_t * dir = NULL;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	STRPTR dir_name,base_name,temp = NULL;
	int error;

	ENTER();

	D(("name = '%b'",MKBADDR(bcpl_name)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_INVALID_COMPONENT_NAME;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to overwrite the root directory, are you kidding? */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot overwrite the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	error = split_path_name(full_name,strlen(full_name),&temp,&dir_name,&base_name);
	if(error != OK)
	{
		D(("could not split path '%s'",escape_name(full_name)));
		goto out;
	}

	D(("path name = '%s'",escape_name(full_name)));
	D(("directory name = '%s'", dir_name));
	D(("base name = '%s'", base_name));

	ln = allocate_lock_node(EXCLUSIVE_LOCK,full_name,user);
	if(ln == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	if(smba_open(ServerData,dir_name,open_read_only,open_dont_truncate,&dir,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	ASSERT( base_name != NULL );

	if(smba_mkdir(dir,base_name,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	smba_close(ServerData,dir);
	dir = NULL;

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	add_lock_node(ln);

	result = MKBADDR(&ln->ln_FileLock);
	SHOWPOINTER(&ln->ln_FileLock);

	full_name = NULL;
	ln = NULL;
	error = OK;

 out:

	if(dir != NULL)
		smba_close(ServerData,dir);

	free_memory(temp);
	free_memory(full_name);
	free_memory(ln);

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static BPTR
Action_LocateObject(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	const void * 			bcpl_name,
	LONG					mode,
	LONG *					error_ptr)
{
	BPTR result = ZERO;
	STRPTR full_name = NULL;
	struct LockNode * ln = NULL;
	STRPTR parent_name;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	int error;

	ENTER();

	D(("name = '%b'",MKBADDR(bcpl_name)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	ln = allocate_lock_node((mode != EXCLUSIVE_LOCK) ? SHARED_LOCK : EXCLUSIVE_LOCK,full_name,user);
	if(ln == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	error = check_access_mode_collision(ln->ln_FullName,ln->ln_FileLock.fl_Access);
	if(error != OK)
		goto out;

	if(smba_open(ServerData,ln->ln_FullName,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	add_lock_node(ln);

	result = MKBADDR(&ln->ln_FileLock);
	SHOWPOINTER(&ln->ln_FileLock);

	SHOWPOINTER(ln->ln_FullName);

	D(("full path name = '%s'",escape_name(ln->ln_FullName)));

	full_name = NULL;
	ln = NULL;
	error = OK;

 out:

	free_memory(full_name);
	free_memory(ln);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static BPTR
Action_CopyDir(
	const struct MsgPort *	user,
	struct FileLock *		lock,
	LONG *					error_ptr)
{
	BPTR result = ZERO;
	STRPTR full_name = NULL;
	struct LockNode * ln = NULL;
	const TEXT * source_name;
	int error;

	ENTER();

	SHOWPOINTER(lock);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* Fail fast if the lock is invalid. */
	if(lock != NULL && lock_is_invalid(lock,&error))
		goto out;

	if(lock != NULL)
	{
		const struct LockNode * key = (struct LockNode *)lock->fl_Key;

		D(("lock on '%s'", escape_name(key->ln_FullName)));
	}
	else
	{
		SHOWMSG("lock on ':' (ZERO lock)");
	}

	/* If a specific lock is to be duplicated, then that
	 * better be a shared lock.
	 */
	if(lock != NULL && lock->fl_Access != SHARED_LOCK)
	{
		SHOWMSG("cannot duplicate exclusive lock");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	/* Duplicate a specific lock? */
	if(lock != NULL)
	{
		struct LockNode * source;

		source = (struct LockNode *)lock->fl_Key;

		source->ln_LastUser = user;

		source_name = source->ln_FullName;
	}
	/* We are asked to duplicate the ZERO lock, which refers
	 * to the disk's root directory.
	 */
	else
	{
		source_name = SMB_ROOT_DIR_NAME;
	}

	full_name = allocate_and_copy_string(source_name, strlen(source_name));
	if(full_name == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	ln = allocate_lock_node(SHARED_LOCK,full_name,user);
	if(ln == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	add_lock_node(ln);

	result = MKBADDR(&ln->ln_FileLock);
	SHOWPOINTER(&ln->ln_FileLock);

	full_name = NULL;
	ln = NULL;
	error = OK;

 out:

	free_memory(full_name);
	free_memory(ln);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_FreeLock(
	struct FileLock *	lock,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	int error = OK;

	ENTER();

	SHOWPOINTER(lock);

	/* Passing ZERO is harmless. But we have to have
	 * a valid lock if we are to proceed with releasing
	 * it.
	 */
	if(lock != NULL)
	{
		const struct LockNode * key;
		struct LockNode * found;
		struct LockNode * ln;
		struct splay_node * sn;

		if(file_system_disabled)
		{
			error = ERROR_NO_DISK;
			goto out;
		}

		if(lock_is_invalid(lock,&error))
			goto out;

		found = NULL;

		key = (struct LockNode *)lock->fl_Key;

		D(("lock on '%s'", escape_name(key->ln_FullName)));

		#ifndef USE_SPLAY_TREE
		{
			for(ln = (struct LockNode *)LockList.mlh_Head ;
				ln->ln_MinNode.mln_Succ != NULL ;
				ln = (struct LockNode *)ln->ln_MinNode.mln_Succ)
			{
				if(ln == key)
				{
					found = ln;
					break;
				}
			}
		}
		#else
		{
			SHOWMSG("looking up the lock address (what happened to trust?)");

			sn = splay_tree_find(&LockAddressTree, (splay_key_t)key);
			if(sn != NULL)
			{
				SHOWMSG("found it");

				found = (struct LockNode *)sn->sn_userdata;
			}
			else
			{
				SHOWMSG("didn't find it (this should never happen)");
			}
		}
		#endif /* USE_SPLAY_TREE */

		/* This should never happen. */
		if(found == NULL)
		{
			error = ERROR_INVALID_LOCK;
			goto out;
		}

		smba_close(ServerData,found->ln_File);

		remove_lock_node(found);

		free_memory(found->ln_FullName);
		free_memory(found);
	}
	else
	{
		SHOWMSG("lock on ':' (ZERO lock)");
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_SameLock(
	const struct MsgPort *	user,
	struct FileLock *		lock1,
	struct FileLock *		lock2,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	const TEXT * name1;
	const TEXT * name2;
	int error = OK;

	ENTER();

	SHOWPOINTER(lock1);
	SHOWPOINTER(lock2);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(lock1 != NULL)
	{
		struct LockNode * ln;

		if(lock_is_invalid(lock1,&error))
			goto out;

		ln = (struct LockNode *)lock1->fl_Key;

		D(("lock1 on '%s'", escape_name(ln->ln_FullName)));

		ln->ln_LastUser = user;

		name1 = ln->ln_FullName;
	}
	else
	{
		name1 = SMB_ROOT_DIR_NAME;
	}

	if(lock2 != NULL)
	{
		struct LockNode * ln;

		if(lock_is_invalid(lock2,&error))
			goto out;

		ln = (struct LockNode *)lock2->fl_Key;

		D(("lock2 on '%s'", escape_name(ln->ln_FullName)));

		ln->ln_LastUser = user;

		name2 = ln->ln_FullName;
	}
	else
	{
		name2 = SMB_ROOT_DIR_NAME;
	}

	D(("name1 = '%s'",escape_name(name1)));
	D(("name2 = '%s'",escape_name(name2)));

	if(compare_names(name1,name2) == SAME)
		result = DOSTRUE;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_SetProtect(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	const void * 			bcpl_name,
	LONG					mask,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR full_name = NULL;
	smba_file_t * file = NULL;
	STRPTR parent_name;
	TEXT name[MAX_FILENAME_LEN+1];
	smba_stat_t st;
	int name_len;
	int error;

	ENTER();

	D(("name = '%b'",MKBADDR(bcpl_name)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to change the protection bits of the root
	 * directory, are you kidding?
	 */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot change protection bits of the root directory");

		error = ERROR_OBJECT_WRONG_TYPE;
		goto out;
	}

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_writable,open_dont_truncate,&file,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	#if DEBUG
	{
		TEXT user_other_bits[11];
		TEXT owner_bits[9];
		int i;

		strlcpy(user_other_bits, "rwed rwed", sizeof(user_other_bits));

		for(i = 8 ; i < 16 ; i++)
		{
			if((mask & (1 << i)) == 0)
			{
				int offset;

				if(i < 12)
					offset = 12 - i;
				else
					offset = 21 - i;

				ASSERT( 0 <= offset && offset < (int)sizeof(user_other_bits) );

				user_other_bits[offset - 1] = '-';
			}
		}

		strlcpy(owner_bits, "hsparwed", sizeof(owner_bits));

		/* hspa */
		for(i = 0 ; i < 4 ; i++)
		{
			if((mask & (1 << (7 - i))) == 0)
				owner_bits[i] = '-';
		}

		/* rwed */
		for(i = 4 ; i < 8 ; i++)
		{
			if((mask & (1 << (7 - i))) != 0)
				owner_bits[i] = '-';
		}

		D(("protection bit mask = 0x%08lx (%s %s)",mask,user_other_bits,owner_bits));
	}
	#endif /* DEBUG */

	memset(&st,0,sizeof(st));

	if((mask & FIBF_DELETE) != 0)
	{
		SHOWMSG("write/delete protection enabled");
		st.is_read_only = TRUE;
	}
	else
	{
		SHOWMSG("write/delete protection disabled");
	}

	/* Careful: the 'archive' attribute has exactly the opposite
	 *          meaning in the Amiga and the SMB worlds.
	 */
	st.was_changed_since_last_archive = ((mask & FIBF_ARCHIVE) == 0);

	if(smba_setattr(file,&st,NULL,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	result = DOSTRUE;
	error = OK;

 out:

	if(file != NULL)
		smba_close(ServerData,file);

	free_memory(full_name);

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_RenameObject(
	const struct MsgPort *	user,
	struct FileLock *		source_lock,
	const void *			source_bcpl_name,
	struct FileLock *		destination_lock,
	const void *			destination_bcpl_name,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR full_source_name = NULL;
	STRPTR full_destination_name = NULL;
	STRPTR parent_source_name = NULL;
	STRPTR parent_destination_name = NULL;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	STRPTR parent_name;
	int error;

	ENTER();

	D(("source name = '%b'",MKBADDR(source_bcpl_name)));
	D(("destination name = '%b'",MKBADDR(destination_bcpl_name)));

	SHOWPOINTER(source_lock);
	SHOWPOINTER(destination_lock);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),source_bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	if(CANNOT get_parent_name(source_lock, user, &parent_name, &error))
		goto out;

	error = build_full_path_name(parent_name,name,name_len,&full_source_name);
	if(error != OK)
		goto out;

	D(("full source path = '%s'",escape_name(full_source_name)));

	/* Trying to rename the root directory, are you kidding? */
	if(strcmp(full_source_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot rename the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),destination_bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_INVALID_COMPONENT_NAME;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	if(CANNOT get_parent_name(destination_lock, user, &parent_name, &error))
		goto out;

	error = build_full_path_name(parent_name,name,name_len,&full_destination_name);
	if(error != OK)
		goto out;

	D(("full destination path = '%s'",escape_name(full_destination_name)));

	/* Trying to replace the root directory, are you kidding? */
	if(strcmp(full_destination_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot replace the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	/* Is this object still in use? If so, renaming it would require
	 * updating the names in all the file locks and file handles which
	 * use it.
	 */
	error = name_already_in_use(full_source_name);
	if(error != OK)
	{
		D(("source '%s' is still in use",escape_name(full_source_name)));

		goto out;
	}

	error = name_already_in_use(full_destination_name);
	if(error != OK)
	{
		D(("destination '%s' is still in use",escape_name(full_destination_name)));

		goto out;
	}

	if(smba_rename(ServerData,full_source_name,full_destination_name,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	get_parent_dir_name(full_source_name,strlen(full_source_name),&parent_source_name);
	get_parent_dir_name(full_destination_name,strlen(full_destination_name),&parent_destination_name);

	/* Restart directory scanning in the source directory from which
	 * the entry was removed unless the entry just changed name, but did
	 * not move to a different directory.
	 */
	if(parent_source_name != NULL && (parent_destination_name == NULL || compare_names(parent_source_name,parent_destination_name) != SAME))
		restart_directory_scanning(user,parent_source_name);

	result = DOSTRUE;
	error = OK;

 out:

	free_memory(full_source_name);
	free_memory(full_destination_name);

	free_memory(parent_source_name);
	free_memory(parent_destination_name);

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_DiskInfo(
	struct InfoData *	id,
	LONG *				error_ptr)
{
	LONG result = DOSTRUE;
	int error = OK;

	ENTER();

	memset(id,0,sizeof(*id));

	/* These defaults (no disk present) will have to do until
	 * we know better...
	 */
	id->id_NumBlocks		= 1;
	id->id_NumBlocksUsed	= 1;
	id->id_BytesPerBlock	= 512;
	id->id_DiskType			= ID_NO_DISK_PRESENT;
	id->id_DiskState		= ID_WRITE_PROTECTED;

	if(NOT file_system_disabled)
	{
		LONG num_blocks_free;
		LONG num_blocks;
		LONG block_size;

		if(smba_statfs(ServerData,&block_size,&num_blocks,&num_blocks_free,&error) >= 0)
		{
			if(NOT WriteProtected)
				id->id_DiskState = ID_VALIDATED;

			SHOWMSG("got the disk data");
			SHOWVALUE(block_size);
			SHOWVALUE(num_blocks);
			SHOWVALUE(num_blocks_free);

			/* Pretend that the block size is 512 bytes, if not provided. */
			if(block_size <= 0)
				block_size = 512;

			if (block_size < 512)
			{
				num_blocks		/= (512 / block_size);
				num_blocks_free	/= (512 / block_size);
			}
			else if (block_size > 512)
			{
				num_blocks		*= (block_size / 512);
				num_blocks_free	*= (block_size / 512);
			}

			id->id_NumBlocks		= num_blocks;
			id->id_NumBlocksUsed	= num_blocks - num_blocks_free;
			id->id_BytesPerBlock	= 512;
			id->id_DiskType			= ID_DOS_DISK;
			id->id_VolumeNode		= MKBADDR(VolumeNode);
			id->id_InUse			= NOT (IsListEmpty((struct List *)&FileList) && IsListEmpty((struct List *)&LockList));

			if(id->id_NumBlocks == 0)
				id->id_NumBlocks = 1;

			if(id->id_NumBlocksUsed == 0)
				id->id_NumBlocksUsed = 1;
		}
		else
		{
			SHOWMSG("could not get any disk data");

			error = map_errno_to_ioerr(error);

			result = DOSFALSE;
		}
	}

	SHOWVALUE(id->id_NumBlocks);
	SHOWVALUE(id->id_NumBlocksUsed);
	SHOWVALUE(id->id_BytesPerBlock);
	SHOWVALUE(id->id_DiskType);
	SHOWVALUE(id->id_VolumeNode);
	SHOWVALUE(id->id_InUse);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

static LONG
Action_Info(
	const struct MsgPort *	user,
	struct FileLock *		lock,
	struct InfoData *		id,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	LONG disk_info_error;
	int error = OK;

	ENTER();

	SHOWPOINTER(lock);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* We need to check if the lock matches the volume node. However,
	 * a ZERO lock is valid, too.
	 */
	if(CANNOT get_parent_name(lock, user, NULL, &error))
		goto out;

	result = Action_DiskInfo(id,&disk_info_error);

	error = disk_info_error;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_ExamineObject(
	const struct MsgPort *	user,
	struct FileLock *		lock,
	struct FileInfoBlock *	fib,
	LONG *					error_ptr)
{
	BOOL is_root_directory = TRUE;
	LONG result = DOSFALSE;
	int error = OK;

	ENTER();

	SHOWPOINTER(lock);

	memset(fib,0,sizeof(*fib));

	fib->fib_DiskKey = -1;

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* If the ZERO lock is involved, it stands in for the
	 * root directory. Otherwise it might be a lock on a
	 * file or directory.
	 */
	if(lock != NULL)
	{
		struct LockNode * ln;
		smba_stat_t st;

		if(lock_is_invalid(lock,&error))
			goto out;

		ln = (struct LockNode *)lock->fl_Key;

		D(("lock on '%s'", escape_name(ln->ln_FullName)));

		ln->ln_LastUser = user;

		if(smba_getattr(ln->ln_File,&st,&error) < 0)
		{
			SHOWMSG("information not available");

			error = map_errno_to_ioerr(error);
			goto out;
		}

		D(("ln->ln_FullName = '%s'",escape_name(ln->ln_FullName)));

		/* Is this a file or directory rather than the root directory? */
		if(strcmp(ln->ln_FullName,SMB_ROOT_DIR_NAME) != SAME)
		{
			QUAD size_quad;
			QUAD num_blocks_quad;
			TEXT translated_name[MAX_FILENAME_LEN+1];
			const TEXT * name;
			int name_len;
			LONG seconds;

			SHOWMSG("file or directory");

			is_root_directory = FALSE;

			name = get_base_name(ln->ln_FullName,strlen(ln->ln_FullName));
			name_len = strlen(name);

			if(NOT ServerData->server.unicode_enabled)
			{
				if(name_len >= (int)sizeof(translated_name))
				{
					D(("name is too long (%ld >= %ld)", name_len, sizeof(translated_name)));

					error = ERROR_BUFFER_OVERFLOW;
					goto out;
				}

				/* Length includes the terminating NUL byte. */
				memcpy(translated_name,name,name_len+1);

				error = translate_smb_name_to_amiga_name(translated_name,name_len,sizeof(translated_name));
				if(error != OK)
				{
					SHOWMSG("name is not acceptable");
					goto out;
				}

				name = translated_name;
				name_len = strlen(name);
			}

			/* Check if this is a usable Amiga file or directory name. */
			error = validate_amigados_file_name(name, name_len);
			if(error != OK)
			{
				SHOWMSG("name contains unacceptable characters");
				goto out;
			}

			/* Will the name fit? */
			if(name_len >= (int)sizeof(fib->fib_FileName))
			{
				D(("name is too long (%ld >= %ld)", name_len, sizeof(fib->fib_FileName)));

				error = ERROR_BUFFER_OVERFLOW;
				goto out;
			}

			/* Store the file/directory name in the form expected
			 * by dos.library.
			 */
			convert_from_c_to_bcpl_string(fib->fib_FileName,sizeof(fib->fib_FileName),name,name_len);

			/* We pretend that the volume uses 512 bytes per
			 * block (or in SMB terms: the sector size is
			 * 512 bytes). The conversion is a bit elaborate
			 * here...
			 */
			size_quad.Low	= st.size_low;
			size_quad.High	= st.size_high;

			/* Round up when dividing by 512. */
			add_64_plus_32_to_64(&size_quad,511,&num_blocks_quad);
			divide_64_by_32(&num_blocks_quad,512,&num_blocks_quad);

			seconds = (st.mtime == 0) ? st.ctime : st.mtime;

			seconds -= UNIX_TIME_OFFSET + get_time_zone_delta();
			if(seconds < 0)
				seconds = 0;

			fib->fib_Date.ds_Days	= (seconds / (24 * 60 * 60));
			fib->fib_Date.ds_Minute	= (seconds % (24 * 60 * 60)) / 60;
			fib->fib_Date.ds_Tick	= (seconds % 60) * TICKS_PER_SECOND;

			fib->fib_DirEntryType	= st.is_dir ? ST_USERDIR : ST_FILE;
			fib->fib_EntryType		= fib->fib_DirEntryType;
			fib->fib_NumBlocks		= num_blocks_quad.Low;
			fib->fib_Size			= truncate_64_bit_position(&size_quad);

			D(("is read only = %s",st.is_read_only ? "yes" : "no"));

			if(st.is_read_only)
				fib->fib_Protection |= FIBF_DELETE;

			/* Careful: the 'archive' attribute has exactly the opposite
			 *          meaning in the Amiga and the SMB worlds.
			 */
			D(("was changed since last_archive = %s",st.was_changed_since_last_archive ? "yes" : "no"));

			if(NOT st.was_changed_since_last_archive)
				fib->fib_Protection |= FIBF_ARCHIVE;

			D(("is directory = %s",st.is_dir ? "yes" : "no"));

			/* If this is a directory, make calls to ExNext() possible. */
			if(st.is_dir)
				fib->fib_DiskKey = 0;
		}
	}
	else
	{
		SHOWMSG("lock on ':' (ZERO lock)");
	}

	/* So this is actually the root directory? */
	if(is_root_directory)
	{
		const TEXT * volume_name;
		int len;

		SHOWMSG("root directory");

		ASSERT( VolumeNode != NULL );

		volume_name = BADDR(VolumeNode->dol_Name);
		len = volume_name[0];

		SHOWPOINTER(volume_name);
		SHOWVALUE(len);

		ASSERT( len < (int)sizeof(fib->fib_FileName) );

		/* Just don't overrun the buffer. */
		if(len >= (int)sizeof(fib->fib_FileName))
		{
			D(("root directory name is too long (%ld >= %ld)", len, sizeof(fib->fib_FileName)));

			error = ERROR_BUFFER_OVERFLOW;
			goto out;
		}

		memcpy(&fib->fib_FileName[1],&volume_name[1],len);
		fib->fib_FileName[0] = len;

		fib->fib_DirEntryType	= ST_ROOT;
		fib->fib_EntryType		= ST_ROOT;
		fib->fib_NumBlocks		= 1;
		fib->fib_DiskKey		= 0;
		fib->fib_Date			= VolumeNode->dol_misc.dol_volume.dol_VolumeDate;
	}

	result = DOSTRUE;
	error = OK;

	D(("fib->fib_FileName = \"%b\"",MKBADDR(fib->fib_FileName)));
	SHOWVALUE(fib->fib_DirEntryType);
	SHOWVALUE(fib->fib_NumBlocks);
	SHOWVALUE(fib->fib_Size);
	SHOWVALUE(fib->fib_DiskKey);

	#if DEBUG
	{
		struct DateTime dat;
		TEXT date[2 * LEN_DATSTRING],time[2 * LEN_DATSTRING];

		memset(&dat,0,sizeof(dat));

		memset(date,0,sizeof(date));
		memset(time,0,sizeof(time));

		dat.dat_Stamp	= fib->fib_Date;
		dat.dat_Format	= FORMAT_DOS;
		dat.dat_StrDate	= date;
		dat.dat_StrTime	= time;

		if(DateToStr(&dat))
		{
			D(("days=%ld/minutes=%ld/ticks=%ld: %s %s", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick, date, time));
		}
		else
		{
			D(("could not convert days=%ld/minutes=%ld/ticks=%ld", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick));
		}

		ASSERT( strlen(date) < LEN_DATSTRING );
		ASSERT( strlen(time) < LEN_DATSTRING );
	}
	#endif /* DEBUG */

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

/* Check if the name is acceptable as an Amiga file name. Note
 * that we do not check the length.
 */
static BOOL
name_is_acceptable(const TEXT * name)
{
	BOOL result = FALSE;
	int c;

	c = name[0];

	/* Empty names are not acceptable. */
	if(c == '\0')
		goto out;

	/* This takes care of "." and "..". */
	if(c == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0')))
		goto out;

	/* Now for embedded '/', ':' and '\' characters. */
	while((c = (*name++)) != '\0')
	{
		if(c == '/' || c == ':' || c == SMB_PATH_SEPARATOR)
			goto out;
	}

	result = TRUE;

 out:

	return(result);
}

/****************************************************************************/

/* This function is called by the directory scanner over and over again
 * until the first entry is acceptable for it. This means that unusable
 * entries can be skipped until eventually either the end of the directory
 * is reached or one entry can be used.
 *
 * Returns FALSE to keep scanning, TRUE to stop scanning.
 */
static int
dir_scan_callback_func_exnext(
	struct FileInfoBlock *	fib,
	int						unused_fpos,
	int						nextpos,
	const TEXT *			name,
	int						eof,
	const smba_stat_t *		st)
{
	int stop_scanning = FALSE;
	int name_len;
	LONG seconds;
	QUAD size_quad;
	QUAD num_blocks_quad;
	TEXT translated_name[MAX_FILENAME_LEN+1];

	ENTER();

	#if DEBUG
	{
		QUAD st_size_quad;

		st_size_quad.Low	= st->size_low;
		st_size_quad.High	= st->size_high;

		D((" '%s'",escape_name(name)));
		D(("   is directory=%s, is read-only=%s, is hidden=%s, size=%s", st->is_dir ? "yes" : "no",st->is_read_only ? "yes" : "no",st->is_hidden ? "yes" : "no",convert_quad_to_string(&st_size_quad)));
		D(("   nextpos=%ld eof=%ld",nextpos,eof));
	}
	#endif /* DEBUG */

	/* Skip file and drawer names that we wouldn't be
	 * able to handle in the first place.
	 */
	if(NOT name_is_acceptable(name))
	{
		D(("   name is not acceptable"));
		goto out;
	}

	if(st->is_hidden && OmitHidden)
	{
		D(("   ignoring hidden directory entry"));
		goto out;
	}

	name_len = strlen(name);

	if(NOT ServerData->server.unicode_enabled)
	{
		if(name_len >= (int)sizeof(translated_name))
		{
			D(("   name is too long (%ld >= %ld)", name_len, sizeof(translated_name)));
			goto out;
		}

		/* Length includes the terminating NUL byte. */
		memcpy(translated_name,name,name_len+1);

		if(translate_smb_name_to_amiga_name(translated_name,name_len,sizeof(translated_name)) != OK)
		{
			D(("   name is not acceptable"));
			goto out;
		}

		name = translated_name;
		name_len = strlen(name);
	}

	/* Check if this is a usable Amiga file or directory name. */
	if(validate_amigados_file_name(name, name_len) != OK)
	{
		D(("   name contains unacceptable characters"));
		goto out;
	}

	/* Is the name too large to fit? */
	if(name_len >= (int)sizeof(fib->fib_FileName))
	{
		D(("   name is too long (%ld >= %ld)", name_len, sizeof(fib->fib_FileName)));
		goto out;
	}

	/* Store the file/directory name in the form expected
	 * by dos.library.
	 */
	convert_from_c_to_bcpl_string(fib->fib_FileName,sizeof(fib->fib_FileName),name,name_len);

	D(("   final name = '%b'", MKBADDR(fib->fib_FileName)));

	/* Convert the size of the file into blocks, with 512 bytes per block. */
	size_quad.Low	= st->size_low;
	size_quad.High	= st->size_high;

	/* Round up when dividing by 512. */
	add_64_plus_32_to_64(&size_quad,511,&num_blocks_quad);
	divide_64_by_32(&num_blocks_quad,512,&num_blocks_quad);

	fib->fib_DirEntryType	= st->is_dir ? ST_USERDIR : ST_FILE;
	fib->fib_EntryType		= fib->fib_DirEntryType;
	fib->fib_NumBlocks		= num_blocks_quad.Low;
	fib->fib_Size			= truncate_64_bit_position(&size_quad);

	if(st->is_read_only)
		fib->fib_Protection |= FIBF_DELETE;

	/* Careful: the 'archive' attribute has exactly the opposite
	 *          meaning in the Amiga (= was archived) and the SMB
	 *          worlds (= needs to be archived), respectively.
	 */
	if(NOT st->was_changed_since_last_archive)
		fib->fib_Protection |= FIBF_ARCHIVE;

	/* If modification time is 0 use creation time instead (cyfm 2009-03-18). */
	seconds = (st->mtime == 0) ? st->ctime : st->mtime;

	seconds -= UNIX_TIME_OFFSET + get_time_zone_delta();
	if(seconds < 0)
		seconds = 0;

	fib->fib_Date.ds_Days	= (seconds / (24 * 60 * 60));
	fib->fib_Date.ds_Minute	= (seconds % (24 * 60 * 60)) / 60;
	fib->fib_Date.ds_Tick	= (seconds % 60) * TICKS_PER_SECOND;

	#if DEBUG
	{
		struct DateTime dat;
		TEXT date[2 * LEN_DATSTRING],time[2 * LEN_DATSTRING];

		memset(&dat,0,sizeof(dat));

		memset(date,0,sizeof(date));
		memset(time,0,sizeof(time));

		dat.dat_Stamp	= fib->fib_Date;
		dat.dat_Format	= FORMAT_DOS;
		dat.dat_StrDate	= date;
		dat.dat_StrTime	= time;

		if(DateToStr(&dat))
		{
			D(("   days=%ld/minutes=%ld/ticks=%ld: %s %s", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick, date, time));
		}
		else
		{
			D(("   could not convert days=%ld/minutes=%ld/ticks=%ld", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick));
		}

		ASSERT( strlen(date) < LEN_DATSTRING );
		ASSERT( strlen(time) < LEN_DATSTRING );
	}
	#endif /* DEBUG */

	/* We received the one single entry which we came for. */
	stop_scanning = TRUE;

 out:

	fib->fib_DiskKey = eof ? -1 : nextpos;

	RETURN(stop_scanning);
	return(stop_scanning);
}

static LONG
Action_ExamineNext(
	const struct MsgPort *	user,
	struct FileLock *		lock,
	struct FileInfoBlock *	fib,
	LONG *					error_ptr)
{
	struct LockNode * ln;
	LONG result = DOSFALSE;
	int error = OK;
	LONG offset;

	ENTER();

	SHOWPOINTER(lock);

	if(file_system_disabled)
	{
		fib->fib_DiskKey = -1;

		error = ERROR_NO_DISK;
		goto out;
	}

	if(lock_is_invalid(lock,&error))
	{
		fib->fib_DiskKey = -1;
		goto out;
	}

	ln = (struct LockNode *)lock->fl_Key;

	D(("lock on '%s'", escape_name(ln->ln_FullName)));

	ln->ln_LastUser = user;

	/* Is the job finished already? */
	if(fib->fib_DiskKey == -1)
	{
		SHOWMSG("scanning finished.");
		error = ERROR_NO_MORE_ENTRIES;
		goto out;
	}

	/* Check if we should restart scanning the directory
	 * contents. This is tricky at best and may produce
	 * irritating results :(
	 */
	if(ln->ln_RestartExamine)
	{
		offset = 0;

		ln->ln_RestartExamine = FALSE;
	}
	else
	{
		offset = fib->fib_DiskKey;
	}

	memset(fib,0,sizeof(*fib));

	SHOWMSG("calling 'smba_readdir'");
	SHOWVALUE(offset);

	smba_readdir(ln->ln_File,offset,fib,(smba_callback_t)dir_scan_callback_func_exnext,NULL,&error);

	if(error != OK)
	{
		SHOWMSG("error whilst scanning");
		SHOWVALUE(error);
		fib->fib_DiskKey = -1;

		error = map_errno_to_ioerr(error);
		goto out;
	}

	/* If the name is not filled in it means that no directory
	 * entry was acceptable for use, and the directory scanner
	 * returned all the entries available. There are no
	 * further entries to be delivered.
	 */
	if(fib->fib_FileName[0] == '\0')
	{
		SHOWMSG("nothing to be read");
		fib->fib_DiskKey = -1;

		error = ERROR_NO_MORE_ENTRIES;
		goto out;
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

/* This is used by the dir_scan_callback_func_exall() function which needs
 * to add new records to the buffer provided to the ExAll() function.
 */
struct ExAllContext
{
	struct ExAllData *		ec_Last;		/* Points to last ExAllData
											 * record, which may need to
											 * be linked up the next
											 * record that is added.
											 */
	UBYTE *					ec_Buffer;		/* This is the buffer we need
											 * to fill.
											 */
	int						ec_BufferSize;	/* How much room there is in
											 * the buffer.
											 */
	int						ec_RecordSize;	/* Each ExAllData record has the
											 * same header size, and the
											 * type of information returned
											 * controls how large that header
											 * is. Here is the header size
											 * we have to use.
											 */
	struct ExAllControl *	ec_Control;		/* This was passed to the
											 * ExAll() function.
											 */
	LONG					ec_Type;		/* This was passed to the
											 * ExAll() function.
											 */
	LONG					ec_Error;		/* If the scanning process has to
											 * be stopped, this is where the
											 * error returned will go.
											 */
};

/* This function is called for every directory entry the directory scanner
 * can find and attempts to convert it into a form usable by ExAll().
 * Unsuitable entries are ignored, and the directory scanner gets another
 * chance to supply a new entry until either the entire directory has been
 * read with nothing to show for it, or the ExAll() buffer has been filled.
 *
 * Returns FALSE to keep scanning, TRUE to stop scanning.
 */
static int
dir_scan_callback_func_exall(
	struct ExAllContext *	ec,
	int						current_pos,
	int						next_pos,
	const TEXT *			name,
	int						eof,	/* if true this means that this is the last entry available. */
	const smba_stat_t *		st)
{
	TEXT translated_name[MAX_FILENAME_LEN+1];
	int stop_scanning = FALSE;
	int name_len;
	int resume_position = next_pos;
	LONG type = ec->ec_Type;
	UBYTE * buffer = ec->ec_Buffer;
	struct ExAllData * ed;
	int complete_record_size;

	ENTER();

	/* We already delivered the last entry? */
	if((LONG)ec->ec_Control->eac_LastKey == -1)
	{
		/* We didn't deliver even one entry? */
		if(ec->ec_Control->eac_Entries == 0)
			ec->ec_Error = ERROR_NO_MORE_ENTRIES;

		eof = TRUE;

		stop_scanning = TRUE;
		goto out;
	}

	#if DEBUG
	{
		QUAD st_size_quad;

		st_size_quad.Low	= st->size_low;
		st_size_quad.High	= st->size_high;

		D((" '%s'",escape_name(name)));
		D(("   is directory=%s, is read-only=%s, is hidden=%s, size=%s", st->is_dir ? "yes" : "no",st->is_read_only ? "yes" : "no",st->is_hidden ? "yes" : "no",convert_quad_to_string(&st_size_quad)));
		D(("   next_pos=%ld eof=%ld",next_pos,eof));
	}
	#endif /* DEBUG */

	/* Skip file and drawer names that we wouldn't be
	 * able to handle in the first place.
	 */
	if(NOT name_is_acceptable(name))
	{
		D(("   name is not acceptable"));
		goto out;
	}

	if(st->is_hidden && OmitHidden)
	{
		D(("   ignoring hidden directory entry"));
		goto out;
	}

	name_len = strlen(name);

	if(NOT ServerData->server.unicode_enabled)
	{
		if(name_len >= (int)sizeof(translated_name))
		{
			D(("   name is too long (%ld >= %ld)", name_len, sizeof(translated_name)));
			goto out;
		}

		/* Length includes the terminating NUL byte. */
		memcpy(translated_name,name,name_len+1);

		if(translate_smb_name_to_amiga_name(translated_name,name_len,sizeof(translated_name)) != OK)
		{
			D(("   name cannot be translated"));
			goto out;
		}

		name = translated_name;
		name_len = strlen(name);
	}

	/* Check if this is a usable Amiga file or directory name. */
	if(validate_amigados_file_name(name, name_len) != OK)
	{
		D(("   name contains unacceptable characters"));
		goto out;
	}

	/* Check if the name matches the pattern provided, if any. */
	if(ec->ec_Control->eac_MatchString != NULL)
	{
		D(("   checking name against match string '%s'", ec->ec_Control->eac_MatchString));

		if(NOT MatchPatternNoCase(ec->ec_Control->eac_MatchString,(STRPTR)name))
		{
			SHOWMSG("   name does not match");
			goto out;
		}
	}

	/* Figure out how large this entry needs to be, and
	 * if necessary stop processing if there is not enough
	 * room left to store it.
	 */
	complete_record_size = ec->ec_RecordSize + name_len+1;

	/* All entries need to begin on a word-aligned address,
	 * which means that we need to pad the entry size to
	 * a multiple of 2.
	 */
	if((complete_record_size % 2) > 0)
		complete_record_size++;

	D(("   buffer size left = %ld, record size = %ld",ec->ec_BufferSize,complete_record_size));

	if(complete_record_size > ec->ec_BufferSize)
	{
		SHOWMSG("   not enough room to return this entry");

		/* If the buffer is still empty, stop the entire process before
		 * it has really begun. Not even one directory entry will fit...
		 */
		if(ec->ec_Control->eac_Entries == 0)
		{
			SHOWMSG("   this was the first read attempt -- aborting");

			ec->ec_Error = ERROR_NO_FREE_STORE;

			eof = TRUE;
		}
		/* No more room to store another entry, but we can deliver
		 * what was already stored. The client can call ExAll()
		 * again and pick up the next entry.
		 */
		else
		{
			/* Assuming that the client wants to know the next
			 * entry, resume with the one which we couldn't store.
			 */
			resume_position = current_pos;

			eof = FALSE;
		}

		stop_scanning = TRUE;
		goto out;
	}

	/* Fill in this entry. */
	ed = (struct ExAllData *)buffer;

	ASSERT( (((ULONG)ed) % 2) == 0 );

	/* Until we know better, assume that this will be
	 * the last list entry.
	 */
	ed->ed_Next = NULL;

	/* Copy the name, including the terminating NUL byte. */
	ed->ed_Name = (STRPTR)&buffer[ec->ec_RecordSize];
	memcpy(ed->ed_Name,name,name_len+1);

	D(("   ed->ed_Name = '%s'", ed->ed_Name));

	/* Fill in as many records as were requested. */
	if(type >= ED_TYPE)
	{
		ed->ed_Type = st->is_dir ? ST_USERDIR : ST_FILE;

		D(("   type=%ld", ed->ed_Type));
	}

	if(type >= ED_SIZE)
	{
		QUAD size_quad;

		size_quad.Low	= st->size_low;
		size_quad.High	= st->size_high;

		ed->ed_Size = truncate_64_bit_position(&size_quad);

		D(("   size=%ld", ed->ed_Size));
	}

	if(type >= ED_PROTECTION)
	{
		ed->ed_Prot = 0;

		D(("   is read only = %s",st->is_read_only ? "yes" : "no"));

		if(st->is_read_only)
			ed->ed_Prot |= FIBF_DELETE;

		/* Careful: the 'archive' attribute has exactly the opposite
		 *          meaning in the Amiga and the SMB worlds.
		 */
		D(("   was changed since last archive = %s",st->was_changed_since_last_archive ? "yes" : "no"));

		if(NOT st->was_changed_since_last_archive)
			ed->ed_Prot |= FIBF_ARCHIVE;

		D(("   protection=0x%08lx", ed->ed_Prot));
	}

	if(type >= ED_DATE)
	{
		LONG seconds;

		/* If modification time is 0 use creation time instead (cyfm 2009-03-18). */
		seconds = (st->mtime == 0) ? st->ctime : st->mtime;

		seconds -= UNIX_TIME_OFFSET + get_time_zone_delta();
		if(seconds < 0)
			seconds = 0;

		ed->ed_Days		= (seconds / (24 * 60 * 60));
		ed->ed_Mins		= (seconds % (24 * 60 * 60)) / 60;
		ed->ed_Ticks	= (seconds % 60) * TICKS_PER_SECOND;

		#if DEBUG
		{
			struct DateTime dat;
			TEXT date[2 * LEN_DATSTRING],time[2 * LEN_DATSTRING];

			memset(&dat,0,sizeof(dat));

			memset(date,0,sizeof(date));
			memset(time,0,sizeof(time));

			dat.dat_Stamp.ds_Days	= ed->ed_Days;
			dat.dat_Stamp.ds_Minute	= ed->ed_Mins;
			dat.dat_Stamp.ds_Tick	= ed->ed_Ticks;
			dat.dat_Format			= FORMAT_DOS;
			dat.dat_StrDate			= date;
			dat.dat_StrTime			= time;

			if(DateToStr(&dat))
			{
				D(("   days=%ld/minutes=%ld/ticks=%ld: %s %s", ed->ed_Days, ed->ed_Mins, ed->ed_Ticks, date, time));
			}
			else
			{
				D(("   could not convert days=%ld/minutes=%ld/ticks=%ld", ed->ed_Days, ed->ed_Mins, ed->ed_Ticks));
			}

			ASSERT( strlen(date) < LEN_DATSTRING );
			ASSERT( strlen(time) < LEN_DATSTRING );
		}
		#endif /* DEBUG */
	}

	if(type >= ED_COMMENT)
	{
		/* If there is no comment, set the comment string
		 * pointer to NULL. This is documented to be the
		 * correct approach.
		 */
		ed->ed_Comment = NULL;

		D(("   comment=NULL"));
	}

	if(type >= ED_OWNER)
	{
		ed->ed_OwnerUID = ed->ed_OwnerGID = 0;

		D(("   user/gid=0/0"));
	}

	if(ec->ec_Control->eac_MatchFunc != NULL)
	{
		LONG match;

		SHOWMSG("   checking if match function accepts the entry");

		/* Note: The order of the parameters passed to the match hook
		 *       function can be somewhat confusing.
		 *
		 *       For standard hook functions, the order of the parameters
		 *       and the registers they go into is hook=A0, object=A2,
		 *       message=A1.
		 *
		 *       However, the documentation for the 'ExAll()' function
		 *       always lists them in ascending order, that is
		 *       hook=A0, message=A1, object=A2, which can lead to
		 *       quite some confusion and strange errors.
		 *
		 *       The parameter order which is correct for the CallHookPkt()
		 *       function is given below: 1. match function (hook),
		 *       2. pointer to type, 3. pointer to ExAllData.
		 */
		PROFILE_OFF();

		match = CallHookPkt(ec->ec_Control->eac_MatchFunc,&type,ed);

		PROFILE_ON();

		if(NO match)
		{
			SHOWMSG("   match function rejected the entry");
			goto out;
		}
	}

	D(("   registering new entry (total=%ld, space left=%ld)", ec->ec_Control->eac_Entries+1, ec->ec_BufferSize - complete_record_size));

	/* Link the previous entry to the current, if there is one. */
	if(ec->ec_Last != NULL)
		ec->ec_Last->ed_Next = ed;

	ec->ec_Last = ed;

	ec->ec_BufferSize -= complete_record_size;

	ASSERT( ec->ec_BufferSize >= 0 );

	ec->ec_Buffer += complete_record_size;

	ec->ec_Control->eac_Entries++;

 out:

	/* Any more entries to deliver or stop right now? */
	if(eof)
		SHOWMSG("   that was the last entry");
	else
		SHOWMSG("   more entries may be available");

	/* If this was the last entry to be delivered (eof != FALSE)
	 * make sure that the next invocation of this function will
	 * cease delivering more directory entries. Otherwise allow
	 * the next call to ExAll() to resume reading more directory
	 * entries.
	 */
	ec->ec_Control->eac_LastKey = eof ? -1 : resume_position;

	RETURN(stop_scanning);
	return(stop_scanning);
}

static LONG
Action_ExamineAll(
	const struct MsgPort *	last_user,
	struct FileLock *		lock,
	UBYTE *					buffer,
	LONG					buffer_size,
	LONG					type,
	struct ExAllControl *	eac,
	LONG *					error_ptr)
{
	struct ExAllData * ed = (struct ExAllData *)buffer;
	LONG call_exall_again = DOSFALSE;
	struct ExAllContext ec;
	struct LockNode * ln;
	int record_size;
	int error = OK;
	int eof = FALSE;
	LONG offset;

	ENTER();

	SHOWPOINTER(lock);
	SHOWPOINTER(buffer);
	SHOWVALUE(buffer_size);
	SHOWVALUE(type);
	SHOWPOINTER(eac);
	SHOWVALUE(eac->eac_LastKey);

	eac->eac_Entries = 0;

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* Check if the lock is suitable. */
	if(lock_is_invalid(lock, &error))
		goto out;

	ln = (struct LockNode *)lock->fl_Key;

	D(("lock on '%s'", escape_name(ln->ln_FullName)));

	ln->ln_LastUser = last_user;

	/* The buffer has to be large enough for at
	 * least the 'next entry' pointer to be stored.
	 */
	if(buffer_size < (LONG)sizeof(ed->ed_Next))
	{
		D(("buffer is far too short (%ld bytes, minimum is %ld).",buffer_size, sizeof(ed->ed_Next)));

		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	/* No next entry yet. */
	ed->ed_Next = NULL;

	if((LONG)eac->eac_LastKey == -1)
	{
		SHOWMSG("scanning already finished.");

		error = ERROR_NO_MORE_ENTRIES;
		goto out;
	}

	/* Is this even a valid type parameter? All supported
	 * type values are > 1.
	 */
	if(type < ED_NAME)
	{
		D(("type %ld is not supported", type));

		error = ERROR_BAD_NUMBER;
		goto out;
	}

	/* Figure out how much space a single directory
	 * entry will always require, with the name not
	 * taken into account yet.
	 */
	switch(type)
	{
		case ED_NAME:

			SHOWMSG("type=name");

			record_size = offsetof(struct ExAllData,ed_Name) + sizeof(ed->ed_Name);
			break;

		case ED_TYPE:

			SHOWMSG("type=type");

			record_size = offsetof(struct ExAllData,ed_Type) + sizeof(ed->ed_Type);
			break;

		case ED_SIZE:

			SHOWMSG("type=size");

			record_size = offsetof(struct ExAllData,ed_Size) + sizeof(ed->ed_Size);
			break;

		case ED_PROTECTION:

			SHOWMSG("type=protection");

			record_size = offsetof(struct ExAllData,ed_Prot) + sizeof(ed->ed_Prot);
			break;

		case ED_DATE:

			SHOWMSG("type=date");

			record_size = offsetof(struct ExAllData,ed_Days) + (sizeof(ed->ed_Days) + sizeof(ed->ed_Mins) + sizeof(ed->ed_Ticks));
			break;

		case ED_COMMENT:

			SHOWMSG("type=comment");

			record_size = offsetof(struct ExAllData,ed_Comment) + sizeof(ed->ed_Comment);
			break;

		case ED_OWNER:
		default:

			/* Note: If the requested type is not known, we default to return
			 *       everything, i.e. ED_OWNER. For this "promotion" to stick,
			 *       we have to update the type field.
			 */
			type = ED_OWNER;

			SHOWMSG("type=owner");

			record_size = offsetof(struct ExAllData,ed_OwnerUID) + (sizeof(ed->ed_OwnerUID) + sizeof(ed->ed_OwnerGID));
			break;
	}

	if(buffer_size < record_size)
	{
		D(("buffer is too short (%ld bytes, record size is %ld).",buffer_size, record_size));

		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	memset(&ec,0,sizeof(ec));

	ec.ec_RecordSize	= record_size;
	ec.ec_Buffer		= buffer;
	ec.ec_BufferSize	= buffer_size;
	ec.ec_Control		= eac;
	ec.ec_Type			= type;

	SHOWVALUE(ec.ec_RecordSize);

	/* If this 0, we start reading the directory contents beginning
	 * with the first entry. A value > 0 is supposed to resume
	 * directory scanning at the given directory entry index.
	 */
	offset = eac->eac_LastKey;

	/* Check if we should restart scanning the directory
	 * contents. This is tricky at best and may produce
	 * irritating results :(
	 */
	if(ln->ln_RestartExamine)
	{
		SHOWMSG("restarting directory scanning");

		offset = 0;

		ln->ln_RestartExamine = FALSE;
	}

	/* Start from the top? Check if the lock actually refers to a directory. */
	if(offset == 0)
	{
		smba_stat_t st;

		SHOWMSG("first invocation");

		SHOWMSG("getting file attributes");
		if(smba_getattr(ln->ln_File,&st,&error) < 0)
		{
			SHOWMSG("didn't work");

			error = map_errno_to_ioerr(error);
			goto out;
		}

		if(NOT st.is_dir)
		{
			SHOWMSG("lock does not refer to a directory");

			error = ERROR_OBJECT_WRONG_TYPE;
			goto out;
		}
	}

	SHOWMSG("calling 'smba_readdir'");
	SHOWVALUE(offset);

	smba_readdir(ln->ln_File,offset,&ec,(smba_callback_t)dir_scan_callback_func_exall,&eof,&error);

	/* Did the smba_readdir() run into trouble? */
	if (error != OK)
	{
		D(("error whilst scanning (errno=%ld)", error));

		error = map_errno_to_ioerr(error);
		goto out;
	}
	/* Did dir_scan_callback_func_exall() run into trouble? */
	else if (ec.ec_Error != OK)
	{
		D(("error whilst scanning (ioerr=%ld)", ec.ec_Error));

		error = ec.ec_Error;
		goto out;
	}

	/* The dir_scan_callback_func_exall() function will set the
	 * last key (directory search position) to -1 when there
	 * are no more entries to be read. If we didn't succeed
	 * in reading anything at all, this means that we have to
	 * throw in the towel...
	 */
	if(eac->eac_Entries == 0 && (LONG)ec.ec_Control->eac_LastKey == -1)
	{
		SHOWMSG("nothing more to be read");

		error = ERROR_NO_MORE_ENTRIES;
		goto out;
	}

	ASSERT( ec.ec_Buffer <= &buffer[buffer_size] );

	SHOWMSG("ok");

	call_exall_again = DOSTRUE;
	error = OK;

 out:

	/* Don't allow ExAll() to call smba_readdir() again. */
	if(call_exall_again == DOSFALSE)
	{
		eac->eac_Entries = 0;
		eac->eac_LastKey = (ULONG)-1;
	}

	#if DEBUG
	{
		int num_entries_found = 0;

		D(("number of entries available = %ld, call ExAll() again = %s",eac->eac_Entries, call_exall_again ? "yes": "no"));

		if(call_exall_again && eac->eac_Entries > 0)
		{
			do
			{
				SHOWSTRING(ed->ed_Name);
				num_entries_found++;

				ed = ed->ed_Next;
			}
			while(ed != NULL);
		}

		ASSERT( eac->eac_Entries == num_entries_found );
	}
	#endif /* DEBUG */

	(*error_ptr) = error;

	RETURN(call_exall_again);
	return(call_exall_again);
}

/****************************************************************************/

static LONG
Action_ExamineAllEnd(
	const struct MsgPort *	last_user,
	struct FileLock *		lock,
	UBYTE *					buffer,
	LONG					buffer_size,
	LONG					type,
	struct ExAllControl *	eac,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	struct LockNode * ln;
	int error = OK;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* Check if the lock is suitable. */
	if(lock_is_invalid(lock,&error))
		goto out;

	ln = (struct LockNode *)lock->fl_Key;

	D(("lock on '%s'", escape_name(ln->ln_FullName)));

	ln->ln_LastUser = last_user;

	/* Make Action_ExamineAll() return no more entries. */
	eac->eac_LastKey = (ULONG)-1;

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_Find(
	const struct MsgPort *	user,
	LONG					action,
	struct FileHandle *		fh,
	struct FileLock *		parent,
	const void *			bcpl_name,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR parent_path = NULL;
	STRPTR full_name = NULL;
	struct FileNode * fn = NULL;
	STRPTR parent_name;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	BOOL create_new_file = FALSE;
	STRPTR temp = NULL;
	smba_stat_t st;
	int error;

	ENTER();

	switch(action)
	{
		case ACTION_FINDINPUT:

			D(("ACTION_FINDINPUT [Open(\"%b\",MODE_OLDFILE)]",MKBADDR(bcpl_name)));
			break;

		case ACTION_FINDOUTPUT:

			D(("ACTION_FINDOUTPUT [Open(\"%b\",MODE_NEWFILE)]",MKBADDR(bcpl_name)));

			create_new_file = TRUE;
			break;

		case ACTION_FINDUPDATE:

			D(("ACTION_FINDUPDATE [Open(\"%b\",MODE_READWRITE)]",MKBADDR(bcpl_name)));
			break;
	}

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		if(action == ACTION_FINDINPUT)
			error = ERROR_OBJECT_NOT_FOUND;
		else
			error = ERROR_INVALID_COMPONENT_NAME;

		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to open the root directory? */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot open the root directory");

		error = ERROR_OBJECT_WRONG_TYPE;
		goto out;
	}

	fn = allocate_file_node((action == ACTION_FINDOUTPUT) ? EXCLUSIVE_LOCK : SHARED_LOCK,full_name,fh,NULL);
	if(fn == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	error = check_access_mode_collision(full_name,fn->fn_Mode);
	if(error != OK)
		goto out;

	D(("full path name = '%s'",escape_name(fn->fn_FullName)));

	/* Open an existing file for write access, create it if
	 * it doesn't exist yet?
	 */
	if(action == ACTION_FINDUPDATE)
	{
		D(("trying to open '%s' for write access, no truncation", full_name));

		if(smba_open(ServerData,full_name,open_writable,open_dont_truncate,&fn->fn_File,&error) < 0)
		{
			int translated_error;

			if(error == error_check_smb_error)
				translated_error = smb_errno(((struct smb_server *)ServerData)->rcls,((struct smb_server *)ServerData)->err);
			else
				translated_error = error;

			if(translated_error == ENOENT)
			{
				/* We couldn't open an existing file, so we'll have to create one. */
				create_new_file = TRUE;

				SHOWMSG("file didn't open, so we'll try to create it without truncating it now");
			}
		}
	}

	/* Create a new file for MODE_NEWFILE or MODE_READWRITE? */
	if(create_new_file)
	{
		STRPTR dir_name,base_name;
		smba_file_t * dir;

		if(WriteProtected)
		{
			error = ERROR_DISK_WRITE_PROTECTED;
			goto out;
		}

		error = split_path_name(full_name,strlen(full_name),&temp,&dir_name,&base_name);
		if(error != OK)
		{
			D(("could not split path '%s'",escape_name(full_name)));
			goto out;
		}

		SHOWMSG("creating a file; finding parent path first");
		D(("dir_name = '%s'",escape_name(dir_name)));

		if(smba_open(ServerData,dir_name,open_read_only,open_dont_truncate,&dir,&error) < 0)
		{
			error = map_errno_to_ioerr(error);
			goto out;
		}

		SHOWMSG("now trying to create the file");
		D(("base name = '%s'",escape_name(base_name)));

		/* Try to create a new file if it does not exist, but if
		 * it exists, can be opened and MODE_NEWFILE is used, set
		 * its size to 0.
		 *
		 * We don't care yet if it can be created, as the real test
		 * will be in opening the file.
		 */
		smba_create(dir,base_name,action == ACTION_FINDOUTPUT,&error);

		smba_close(ServerData,dir);
	}

	/* The file may have been opened for ACTION_FINDUPDATE already,
	 * so don't reopen it by mistake.
	 */
	if(fn->fn_File == NULL)
	{
		/* Open the file for read access if MODE_OLDFILE is used and
		 * for write access if MODE_NEWFILE or MODE_READWRITE
		 * is used.
		 *
		 * If the file opens and MODE_NEWFILE is used, set the
		 * file size to 0.
		 */
		if(smba_open(ServerData,full_name,(action != ACTION_FINDINPUT),(action == ACTION_FINDOUTPUT),&fn->fn_File,&error) < 0)
		{
			error = map_errno_to_ioerr(error);
			goto out;
		}
	}

	/* Make sure that we ended opening a file, and not a directory.
	 * Embarrassing questions might otherwise be asked later...
	 */
	if(smba_getattr(fn->fn_File,&st,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	if(st.is_dir)
	{
		D(("ouch: '%s' is a directory, not a file",escape_name(full_name)));

		error = ERROR_OBJECT_WRONG_TYPE;
		goto out;
	}

	D(("all clear: '%s' is a file and not a directory",escape_name(full_name)));

	fh->fh_Arg1 = (LONG)fn;

	add_file_node(fn);

	result = DOSTRUE;

	full_name = NULL;
	fn = NULL;
	error = OK;

 out:

	free_memory(temp);
	free_memory(full_name);
	free_memory(fn);
	free_memory(parent_path);

	/* This can never be a read protection error (EACCES) for
	 * ACTION_FINDOUTPUT.
	 */
	if(error == ERROR_READ_PROTECTED && action == ACTION_FINDOUTPUT)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_Read(
	struct FileNode *	fn,
	APTR				mem,
	LONG				length,
	LONG *				error_ptr)
{
	LONG result = 0;
	int error = OK;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	SHOWVALUE(length);

	if(length > 0)
	{
		result = smba_read(fn->fn_File,mem,length,&fn->fn_OffsetQuad,&error);
		if(result < 0)
		{
			error = map_errno_to_ioerr(error);

			result = -1;
			goto out;
		}

		add_64_plus_32_to_64(&fn->fn_OffsetQuad, result, &fn->fn_OffsetQuad);
	}

	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_Write(
	struct FileNode *	fn,
	APTR				mem,
	LONG				length,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	int error = OK;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	SHOWVALUE(length);

	if(length > 0)
	{
		result = smba_write(fn->fn_File,mem,length,&fn->fn_OffsetQuad,&error);
		if(result < 0)
		{
			error = map_errno_to_ioerr(error);

			result = -1;
			goto out;
		}

		add_64_plus_32_to_64(&fn->fn_OffsetQuad, result, &fn->fn_OffsetQuad);
	}

	error = OK;

 out:

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_End(
	struct FileNode *	which_fn,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	struct FileNode * fn;
	struct FileNode * found;
	struct splay_node * sn;
	int error = OK;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(which_fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(which_fn->fn_FullName)));

	/* Make sure that the file is still open. This is to avoid
	 * trouble if the client ends up trying to close the
	 * same file twice.
	 */
	found = NULL;

	#ifndef USE_SPLAY_TREE
	{
		for(fn = (struct FileNode *)FileList.mlh_Head ;
		    fn->fn_MinNode.mln_Succ != NULL ;
		    fn = (struct FileNode *)fn->fn_MinNode.mln_Succ)
		{
			if(fn == which_fn)
			{
				found = fn;
				break;
			}
		}
	}
	#else
	{
		SHOWMSG("looking up the file address (what happened to trust?)");

		sn = splay_tree_find(&FileAddressTree, (splay_key_t)which_fn);
		if(sn != NULL)
		{
			SHOWMSG("found it");

			found = (struct FileNode *)sn->sn_userdata;
		}
		else
		{
			SHOWMSG("didn't find it (this should never happen)");
		}
	}
	#endif /* USE_SPLAY_TREE */

	if(found == NULL)
	{
		SHOWMSG("file not known");

		error = ERROR_INVALID_LOCK;
		goto out;
	}

	remove_file_node(found);

	smba_close(ServerData,found->fn_File);

	/* This will make the file_is_invalid() tests return
	 * TRUE, which should make it easier to detect
	 * files which have been closed already, should the
	 * file system receive them.
	 */
	found->fn_Magic = 0;

	free_memory(found->fn_FullName);
	free_memory(found);

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_Seek(
	struct FileNode *	fn,
	LONG				position,
	LONG				mode,
	LONG *				error_ptr)
{
	QUAD previous_position_quad;
	QUAD reference_position_quad;
	QUAD new_position_quad;
	LONG result = -1;
	smba_stat_t st;
	int error;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	previous_position_quad = fn->fn_OffsetQuad;

	switch(mode)
	{
		case OFFSET_BEGINNING:

			reference_position_quad.Low		= 0;
			reference_position_quad.High	= 0;

			break;

		case OFFSET_CURRENT:

			reference_position_quad = fn->fn_OffsetQuad;

			break;

		case OFFSET_END:

			if(smba_getattr(fn->fn_File,&st,&error) < 0)
			{
				error = map_errno_to_ioerr(error);
				goto out;
			}

			reference_position_quad.Low		= st.size_low;
			reference_position_quad.High	= st.size_high;

			break;

		default:

			D(("seek mode %ld not known", mode));

			error = ERROR_ACTION_NOT_KNOWN;
			goto out;
	}

	#if DEBUG
	{
		const TEXT * mode_name;

		switch(mode)
		{
			case OFFSET_BEGINNING:

				mode_name = "OFFSET_BEGINNING";
				break;

			case OFFSET_CURRENT:

				mode_name = "OFFSET_CURRENT";
				break;

			default:

				mode_name = "OFFSET_END";
				break;
		}

		D(("Seek(..., %ld, %s); current position = %s", position, mode_name, convert_quad_to_string(&reference_position_quad)));
	}
	#endif /* DEBUG */

	if(position < 0)
	{
		QUAD position_quad;

		position_quad.Low	= -position;
		position_quad.High	= 0;

		/* We cannot seek back beyond the beginning of the file. */
		if(compare_64_to_64(&reference_position_quad,&position_quad) < 0)
		{
			SHOWMSG("cannot seek back beyond the beginning of the file.");

			error = ERROR_SEEK_ERROR;
			goto out;
		}

		subtract_64_from_64_to_64(&reference_position_quad,&position_quad,&new_position_quad);
	}
	else
	{
		/* Careful, we need to check for overflow, too. */
		if(add_64_plus_32_to_64(&reference_position_quad,position,&new_position_quad) > 0)
		{
			SHOWMSG("position is too large");

			error = ERROR_SEEK_ERROR;
			goto out;
		}
	}

	error = OK;

	fn->fn_OffsetQuad = new_position_quad;

	result = truncate_64_bit_position(&previous_position_quad);

	D(("new position = %s; returning %ld", convert_quad_to_string(&new_position_quad), result));

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_SetFileSize(
	struct FileNode *	fn,
	LONG				position,
	LONG				mode,
	LONG *				error_ptr)
{
	QUAD previous_position_quad;
	QUAD reference_position_quad;
	QUAD new_position_quad;
	LONG result = -1;
	smba_stat_t st;
	int error;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	previous_position_quad = fn->fn_OffsetQuad;

	switch(mode)
	{
		case OFFSET_BEGINNING:

			reference_position_quad.Low		= 0;
			reference_position_quad.High	= 0;

			break;

		case OFFSET_CURRENT:

			reference_position_quad = fn->fn_OffsetQuad;

			break;

		case OFFSET_END:

			if(smba_getattr(fn->fn_File,&st,&error) < 0)
			{
				error = map_errno_to_ioerr(error);
				goto out;
			}

			reference_position_quad.Low		= st.size_low;
			reference_position_quad.High	= st.size_high;

			break;

		default:

			error = ERROR_ACTION_NOT_KNOWN;
			goto out;
	}

	if(position < 0)
	{
		QUAD position_quad;

		position_quad.Low	= -position;
		position_quad.High	= 0;

		/* We cannot seek back beyond the beginning of the file. */
		if(compare_64_to_64(&reference_position_quad,&position_quad) < 0)
		{
			error = ERROR_SEEK_ERROR;
			goto out;
		}

		subtract_64_from_64_to_64(&reference_position_quad,&position_quad,&new_position_quad);
	}
	else
	{
		/* Careful, we need to check for overflow, too. */
		if(add_64_plus_32_to_64(&reference_position_quad,position,&new_position_quad) > 0)
		{
			error = ERROR_SEEK_ERROR;
			goto out;
		}
	}

	if(smba_setattr(fn->fn_File,NULL,&new_position_quad,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	error = OK;

	/* If the current seek position reaches beyond the new
	 * size of the file, move it to the end of the file.
	 */
	if(compare_64_to_64(&fn->fn_OffsetQuad,&new_position_quad) > 0)
		fn->fn_OffsetQuad = new_position_quad;

	result = truncate_64_bit_position(&previous_position_quad);

 out:

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_SetDate(
	const struct MsgPort *		user,
	struct FileLock *			parent,
	const void *				bcpl_name,
	const struct DateStamp *	ds,
	LONG *						error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR full_name = NULL;
	smba_file_t * file = NULL;
	STRPTR parent_name;
	TEXT name[MAX_FILENAME_LEN+1];
	smba_stat_t st;
	LONG seconds;
	int name_len;
	int error;

	ENTER();

	D(("name = '%b'",MKBADDR(bcpl_name)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to change the date of the root directory? */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot change the date of the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_writable,open_dont_truncate,&file,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	if(smba_getattr(file,&st,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	#if DEBUG
	{
		struct DateTime dat;
		TEXT date[2 * LEN_DATSTRING],time[2 * LEN_DATSTRING];

		memset(&dat,0,sizeof(dat));

		memset(date,0,sizeof(date));
		memset(time,0,sizeof(time));

		dat.dat_Stamp	= (*ds);
		dat.dat_Format	= FORMAT_DOS;
		dat.dat_StrDate	= date;
		dat.dat_StrTime	= time;

		if(DateToStr(&dat))
		{
			D(("days=%ld/minutes=%ld/ticks=%ld: %s %s", ds->ds_Days, ds->ds_Minute, ds->ds_Tick, date, time));
		}
		else
		{
			D(("could not convert days=%ld/minutes=%ld/ticks=%ld", ds->ds_Days, ds->ds_Minute, ds->ds_Tick));
		}

		ASSERT( strlen(date) < LEN_DATSTRING );
		ASSERT( strlen(time) < LEN_DATSTRING );
	}
	#endif /* DEBUG */

	seconds = (ds->ds_Days * 24 * 60 + ds->ds_Minute) * 60 + (ds->ds_Tick / TICKS_PER_SECOND);

	/* We change both the creation date/time and the last modification
	 * date/time because the SMB server may not initialize all four
	 * date/time records for ACTION_EXAMINE/ACTION_EXNEXT/ACTION_EXAMINE_ALL
	 * to use. The modification date/time may be missing, so the
	 * creation date/time is used in its stead.
	 *
	 * Unless we initialize it here, the ACTION_EXAMINE/ACTION_EXNEXT/ACTION_EXAMINE_ALL
	 * 'Date file last changed' may always end up using the creation time.
	 */
	st.ctime = seconds + UNIX_TIME_OFFSET + get_time_zone_delta();
	st.mtime = st.ctime;
	st.atime = 0;

	D(("ctime = mtime = %lu",st.ctime));

	if(smba_setattr(file,&st,NULL,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	result = DOSTRUE;
	error = OK;

 out:

	if(file != NULL)
		smba_close(ServerData,file);

	free_memory(full_name);

	/* This can never be a read protection error (EACCES). */
	if(error == ERROR_READ_PROTECTED)
		error = ERROR_WRITE_PROTECTED;

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_ExamineFH(
	struct FileNode *		fn,
	struct FileInfoBlock *	fib,
	LONG *					error_ptr)
{
	QUAD size_quad;
	QUAD num_blocks_quad;
	LONG result = DOSFALSE;
	smba_stat_t st;
	int error;
	LONG seconds;
	TEXT translated_name[MAX_FILENAME_LEN+1];
	const TEXT * name;
	int name_len;

	ENTER();

	memset(fib,0,sizeof(*fib));

	fib->fib_DiskKey = -1;

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	if(smba_getattr(fn->fn_File,&st,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	name = get_base_name(fn->fn_FullName,strlen(fn->fn_FullName));
	name_len = strlen(name);

	if(NOT ServerData->server.unicode_enabled)
	{
		if(name_len >= (int)sizeof(translated_name))
		{
			D(("name is too long (%ld >= %ld)", name_len, sizeof(translated_name)));

			error = ERROR_BUFFER_OVERFLOW;
			goto out;
		}

		/* Length includes the terminating NUL byte. */
		memcpy(translated_name,name,name_len+1);

		error = translate_smb_name_to_amiga_name(translated_name,name_len,sizeof(translated_name));
		if(error != OK)
		{
			SHOWMSG("name is not acceptable");
			goto out;
		}

		name = translated_name;
		name_len = strlen(name);
	}

	/* Check if this is a usable Amiga file or directory name. */
	error = validate_amigados_file_name(name, name_len);
	if(error != OK)
	{
		SHOWMSG("name contains unacceptable characters");
		goto out;
	}

	/* Will the name fit? */
	if(name_len >= (int)sizeof(fib->fib_FileName))
	{
		D(("name is too long (%ld >= %ld)", name_len, sizeof(fib->fib_FileName)));

		error = ERROR_BUFFER_OVERFLOW;
		goto out;
	}

	/* Store the file/directory name in the form expected
	 * by dos.library.
	 */
	convert_from_c_to_bcpl_string(fib->fib_FileName,sizeof(fib->fib_FileName),name,name_len);

	/* Convert the size of the file into blocks, with 512 bytes per block. */
	size_quad.Low	= st.size_low;
	size_quad.High	= st.size_high;

	/* Round up when dividing by 512. */
	add_64_plus_32_to_64(&size_quad,511,&num_blocks_quad);
	divide_64_by_32(&num_blocks_quad,512,&num_blocks_quad);

	fib->fib_DirEntryType	= ST_FILE;
	fib->fib_EntryType		= ST_FILE;
	fib->fib_NumBlocks		= num_blocks_quad.Low;
	fib->fib_Size			= truncate_64_bit_position(&size_quad);

	D(("is read only = %s",st.is_read_only ? "yes" : "no"));

	if(st.is_read_only)
		fib->fib_Protection |= FIBF_DELETE;

	/* Careful: the 'archive' attribute has exactly the opposite
	 *          meaning in the Amiga and the SMB worlds.
	 */
	D(("was changed since last_archive = %s",st.was_changed_since_last_archive ? "yes" : "no"));

	if(NOT st.was_changed_since_last_archive)
		fib->fib_Protection |= FIBF_ARCHIVE;

	/* If modification time is 0 use creation time instead (cyfm 2009-03-18). */
	seconds = (st.mtime == 0 ? st.ctime : st.mtime);

	seconds -= UNIX_TIME_OFFSET + get_time_zone_delta();
	if(seconds < 0)
		seconds = 0;

	fib->fib_Date.ds_Days	= (seconds / (24 * 60 * 60));
	fib->fib_Date.ds_Minute	= (seconds % (24 * 60 * 60)) / 60;
	fib->fib_Date.ds_Tick	= (seconds % 60) * TICKS_PER_SECOND;

	#if DEBUG
	{
		struct DateTime dat;
		TEXT date[2 * LEN_DATSTRING],time[2 * LEN_DATSTRING];

		memset(&dat,0,sizeof(dat));

		memset(date,0,sizeof(date));
		memset(time,0,sizeof(time));

		dat.dat_Stamp	= fib->fib_Date;
		dat.dat_Format	= FORMAT_DOS;
		dat.dat_StrDate	= date;
		dat.dat_StrTime	= time;

		if(DateToStr(&dat))
		{
			D(("days=%ld/minutes=%ld/ticks=%ld: %s %s", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick, date, time));
		}
		else
		{
			D(("could not convert days=%ld/minutes=%ld/ticks=%ld", fib->fib_Date.ds_Days, fib->fib_Date.ds_Minute, fib->fib_Date.ds_Tick));
		}

		ASSERT( strlen(date) < LEN_DATSTRING );
		ASSERT( strlen(time) < LEN_DATSTRING );
	}
	#endif /* DEBUG */

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static BPTR
Action_ParentFH(
	struct MsgPort *	user,
	struct FileNode *	fn,
	LONG *				error_ptr)
{
	BPTR result = ZERO;
	struct LockNode * ln = NULL;
	int error;
	STRPTR parent_dir_name = NULL;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	error = get_parent_dir_name(fn->fn_FullName,strlen(fn->fn_FullName),&parent_dir_name);
	if(error != OK)
		goto out;

	ln = allocate_lock_node(SHARED_LOCK,parent_dir_name,user);
	if(ln == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	D(("parent_dir_name = '%s'",escape_name(parent_dir_name)));

	if(smba_open(ServerData,parent_dir_name,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	add_lock_node(ln);

	result = MKBADDR(&ln->ln_FileLock);
	SHOWPOINTER(&ln->ln_FileLock);

	parent_dir_name = NULL;
	ln = NULL;
	error = OK;

 out:

	free_memory(ln);
	free_memory(parent_dir_name);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static BPTR
Action_CopyDirFH(
	const struct MsgPort *	user,
	struct FileNode *		fn,
	LONG *					error_ptr)
{
	BPTR result = ZERO;
	struct LockNode * ln = NULL;
	STRPTR full_name = NULL;
	int error;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	if(fn->fn_Mode != SHARED_LOCK)
	{
		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	full_name = allocate_and_copy_string(fn->fn_FullName, strlen(fn->fn_FullName));
	if(full_name == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	ln = allocate_lock_node(SHARED_LOCK,full_name,user);
	if(ln == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_read_only,open_dont_truncate,&ln->ln_File,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	add_lock_node(ln);

	result = MKBADDR(&ln->ln_FileLock);
	SHOWPOINTER(&ln->ln_FileLock);

	full_name = NULL;
	ln = NULL;
	error = OK;

 out:

	free_memory(ln);
	free_memory(full_name);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_FHFromLock(
	struct FileHandle *	fh,
	struct FileLock *	fl,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	struct FileNode * fn;
	struct LockNode * ln;
	int error = OK;

	ENTER();

	SHOWPOINTER(fl);

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(lock_is_invalid(fl,&error))
		goto out;

	ln = (struct LockNode *)fl->fl_Key;

	D(("lock on '%s'", escape_name(ln->ln_FullName)));

	/* Is this a directory and not a file? */
	if((ln->ln_File->dirent.attr & SMB_FILE_ATTRIBUTE_DIRECTORY) != 0)
	{
		SHOWMSG("this is not a lock for a file");

		error = ERROR_OBJECT_WRONG_TYPE;
		goto out;
	}

	fn = allocate_file_node(fl->fl_Access,ln->ln_FullName,fh,ln->ln_File);
	if(fn == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	/* The file handle absorbs the lock, which in this case includes
	 * the full path name and the SMB file.
	 */
	remove_lock_node(ln);

	ln->ln_FullName = NULL;
	free_memory(ln);

	fh->fh_Arg1 = (LONG)fn;

	add_file_node(fn);

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_RenameDisk(
	const void *	bcpl_name,
	LONG *			error_ptr)
{
	LONG result = DOSFALSE;
	int error;
	STRPTR old_name;
	STRPTR new_name;
	const TEXT * name;
	int len;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(NOT VolumeNodeAdded)
	{
		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	D(("name = '%b'",MKBADDR(bcpl_name)));

	name = bcpl_name;

	len = name[0];

	/* Is this a proper name for a volume? */
	if(NOT is_valid_device_name(name, len))
	{
		error = ERROR_INVALID_COMPONENT_NAME;
		goto out;
	}

	/* Now for the really interesting part; the new name
	 * is to be a NUL-terminated BCPL string, and as such
	 * must be allocated via AllocVec().
	 */
	new_name = AllocVec(1 + len + 1,MEMF_ANY|MEMF_PUBLIC);
	if(new_name == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto out;
	}

	new_name[0] = len;
	memcpy(&new_name[1],&name[1],len);
	new_name[len+1] = '\0';

	Forbid();

	old_name = BADDR(VolumeNode->dol_Name);
	VolumeNode->dol_Name = MKBADDR(new_name);

	Permit();

	FreeVec(old_name);

	if(VolumeNodeAdded)
		send_disk_change_notification(IECLASS_DISKINSERTED);

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_CurrentVolume(
	struct FileNode *	fn,
	LONG *				error_ptr)
{
	LONG result = ZERO;
	int error;

	ENTER();

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	if(NOT VolumeNodeAdded)
	{
		error = ERROR_ACTION_NOT_KNOWN;
		goto out;
	}

	/* This is in support of the "Please insert volume XXXin any drive"
	 * requester. Not that it should be needed, but you never know...
	 */

	result	= MKBADDR(VolumeNode);
	error	= 0; /* This is actually the unit number. */

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_ChangeMode(
	const struct MsgPort *	user,
	LONG					type,
	APTR					object,
	LONG					new_mode,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	struct FileLock * fl = NULL;
	struct FileNode * fn = NULL;
	struct LockNode * ln = NULL;
	const TEXT * name;
	LONG old_mode;
	int error = OK;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	/* Bug compatibility: the ChangeMode() autodocs used to suggest that the
	 * 'new_mode' parameter should contain the new access mode without actually
	 * explaining what that mode should be. Consequently, no two file systems
	 * out of three are implementing this packet the same way.
	 *
	 * Some file systems allow SHARED_LOCK/EXCLUSIVE_LOCK for both file handles
	 * and file locks, some try to allow MODE_OLDFILE/MODE_READWRITE/MODE_NEWFILE
	 * for file handles but really assume that it should be SHARED_LOCK/EXCLUSIVE_LOCK
	 * with hilarious/tragic consequences. The only file system which sort of got
	 * this right was ram-handler.
	 *
	 * We accept MODE_OLDFILE, MODE_READWRITE and MODE_NEWFILE for files, as well
	 * as SHARED_LOCK and EXCLUSIVE_LOCK. This works because these five modes
	 * are represented by different numbers.
	 *
	 * For locks we only accept SHARED_LOCK and EXCLUSIVE_LOCK.
	 */
	if(type == CHANGE_FH)
	{
		/* We convert what we know and let the unexpected through
		 * to produce an error.
		 */
		if(new_mode == MODE_OLDFILE || new_mode == MODE_READWRITE)
			new_mode = SHARED_LOCK;
		else if (new_mode == MODE_NEWFILE)
			new_mode = EXCLUSIVE_LOCK;
	}

	/* Sanity check; verify parameters */
	if((type != CHANGE_LOCK && type != CHANGE_FH) ||
	   (new_mode != EXCLUSIVE_LOCK && new_mode != SHARED_LOCK))
	{
		error = ERROR_ACTION_NOT_KNOWN;
		goto out;
	}

	/* Now obtain the data structures, name and mode
	 * associated with the object in question.
	 */
	if(type == CHANGE_LOCK)
	{
		if(lock_is_invalid(fl,&error))
			goto out;

		fl = object;

		ln = (struct LockNode *)fl->fl_Key;

		D(("lock on '%s'", escape_name(ln->ln_FullName)));

		name = ln->ln_FullName;
		old_mode = fl->fl_Access;

		ln->ln_LastUser = user;
	}
	else
	{
		struct FileHandle * fh = object;

		fn = (struct FileNode *)fh->fh_Arg1;

		if(file_is_invalid(fn,&error))
			goto out;

		D(("file opened on '%s'", escape_name(fn->fn_FullName)));

		name = fn->fn_FullName;
		old_mode = fn->fn_Mode;
	}

	/* Do we need to change anything at all? */
	if(new_mode != old_mode)
	{
		/* Change from shared to exclusive access? */
		if(new_mode != SHARED_LOCK)
		{
			/* Is there another shared access lock
			 * which refers to the same object?
			 */
			if(find_lock_node_by_name(name,ln) != NULL)
			{
				error = ERROR_OBJECT_IN_USE;
				goto out;
			}

			/* Is there another shared access file
			 * which refers to the same object?
			 */
			if(find_file_node_by_name(name,fn) != NULL)
			{
				error = ERROR_OBJECT_IN_USE;
				goto out;
			}
		}

		/* There is either just one single reference
		 * to this object or the object in question
		 * is configured for exclusive access.
		 */
		if(type == CHANGE_LOCK)
			fl->fl_Access = new_mode;
		else
			fn->fn_Mode = new_mode;
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_WriteProtect(
	LONG	flag,
	ULONG	key,
	LONG *	error_ptr)
{
	LONG result = DOSFALSE;
	int error;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(flag == DOSFALSE)
	{
		if(WriteProtected)
		{
			if(key != WriteProtectKey)
			{
				error = ERROR_INVALID_LOCK;
				goto out;
			}

			WriteProtected = FALSE;

			if(VolumeNodeAdded)
			{
				send_disk_change_notification(IECLASS_DISKREMOVED);
				send_disk_change_notification(IECLASS_DISKINSERTED);
			}
		}
	}
	else
	{
		if(NOT WriteProtected)
		{
			WriteProtected = TRUE;
			WriteProtectKey = key;

			if(VolumeNodeAdded)
			{
				send_disk_change_notification(IECLASS_DISKREMOVED);
				send_disk_change_notification(IECLASS_DISKINSERTED);
			}
		}
		else
		{
			error = ERROR_INVALID_LOCK;
			goto out;
		}
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_MoreCache(
	LONG	buffer_delta,
	LONG *	error_ptr)
{
	LONG result;
	int old_size;

	ENTER();

	old_size = smba_get_dircache_size(ServerData);

	result = smba_change_dircache_size(ServerData,old_size + buffer_delta);
	if(result == old_size && buffer_delta != 0)
	{
		result = DOSFALSE;
		(*error_ptr) = ERROR_NO_FREE_STORE;
	}

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_SetComment(
	const struct MsgPort *	user,
	struct FileLock *		parent,
	const void *			bcpl_name,
	const void *			bcpl_comment,
	LONG *					error_ptr)
{
	LONG result = DOSFALSE;
	STRPTR full_name = NULL;
	smba_file_t * file = NULL;
	STRPTR parent_name;
	TEXT name[MAX_FILENAME_LEN+1];
	int name_len;
	int error;

	ENTER();

	D(("name = '%b', comment = '%b'",MKBADDR(bcpl_name),MKBADDR(bcpl_comment)));

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(WriteProtected)
	{
		error = ERROR_DISK_WRITE_PROTECTED;
		goto out;
	}

	if(CANNOT get_parent_name(parent, user, &parent_name, &error))
		goto out;

	name_len = convert_from_bcpl_to_c_string(name,sizeof(name),bcpl_name);

	if(path_name_is_invalid(name, name_len))
	{
		D(("'%s' is not a valid path name", name));

		error = ERROR_OBJECT_NOT_FOUND;
		goto out;
	}

	if(NOT ServerData->server.unicode_enabled)
	{
		error = translate_amiga_name_to_smb_name(name,name_len,sizeof(name));
		if(error != OK)
			goto out;
	}

	error = build_full_path_name(parent_name,name,name_len,&full_name);
	if(error != OK)
		goto out;

	/* Trying to change the comment of the root directory? */
	if(strcmp(full_name, SMB_ROOT_DIR_NAME) == SAME)
	{
		SHOWMSG("cannot change the comment of the root directory");

		error = ERROR_OBJECT_IN_USE;
		goto out;
	}

	D(("full_name = '%s'",escape_name(full_name)));

	if(smba_open(ServerData,full_name,open_writable,open_dont_truncate,&file,&error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	/* All this work and we're only doing something very silly... */
	result = DOSTRUE;
	error = OK;

 out:

	if(file != NULL)
		smba_close(ServerData,file);

	free_memory(full_name);

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_LockRecord(
	struct FileNode *	fn,
	LONG				offset,
	LONG				length,
	LONG				mode,
	ULONG				timeout,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	int error;
	LONG umode;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	/* Sanity checks... */
	if(mode < REC_EXCLUSIVE || mode > REC_SHARED_IMMED)
	{
		error = ERROR_ACTION_NOT_KNOWN;
		goto out;
	}

	/* Invalid offset, size or integer overflow? */
	if(offset < 0 || length <= 0 || offset + length < offset)
	{
		error = ERROR_LOCK_COLLISION;
		goto out;
	}

	if((mode == REC_SHARED) || (mode == REC_SHARED_IMMED))
		umode = 1;
	else
		umode = 0;

	if((mode == REC_SHARED_IMMED) || (mode == REC_EXCLUSIVE_IMMED))
		timeout = 0;

	/* If a timeout was given, it must be converted from ticks
	 * per second into milliseconds.
	 */
	if(timeout > 0)
	{
		/* Is the timeout too large to be converted into
		 * milliseconds?
		 */
		if(timeout > 0xFFFFFFFFUL / TICKS_PER_SECOND)
			timeout = ~0UL;	/* wait forever */
		else
			timeout *= 1000 / TICKS_PER_SECOND;
	}

	if(smba_lockrec (fn->fn_File, offset, length, umode, 0, (long)timeout, &error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

static LONG
Action_FreeRecord(
	struct FileNode *	fn,
	LONG				offset,
	LONG				length,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	int error;

	ENTER();

	if(file_system_disabled)
	{
		error = ERROR_NO_DISK;
		goto out;
	}

	if(file_is_invalid(fn,&error))
		goto out;

	D(("file opened on '%s'", escape_name(fn->fn_FullName)));

	/* Sanity checks... */
	if(offset < 0 || length <= 0 || offset + length < offset)
	{
		error = ERROR_RECORD_NOT_LOCKED;
		goto out;
	}

	if(smba_lockrec (fn->fn_File, offset, length, 2, -1, 0, &error) < 0)
	{
		error = map_errno_to_ioerr(error);
		goto out;
	}

	result = DOSTRUE;
	error = OK;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

/****************************************************************************/

#if defined(ACTION_FILESYSTEM_ATTR)

static LONG
Action_FilesystemAttr(
	struct TagItem *	args,
	LONG *				error_ptr)
{
	LONG result = DOSFALSE;
	struct TagItem * tags = args;
	struct TagItem * ti;
	ULONG * data;
	ULONG length;
	LONG error = OK;

	ENTER();

	while((ti = NextTagItem(&tags)) != NULL)
	{
		data = (ULONG *)ti->ti_Data;

		switch(ti->ti_Tag)
		{
			case FSA_MaxFileNameLengthR:

				(*data) = MaxNameLen > 0 ? MaxNameLen : sizeof(((struct FileInfoBlock *)0)->fib_FileName)-1;

				D(("FSA_MaxFileNameLengthR = %ld", (*data)));

				break;

			case FSA_DOSTypeR:

				(*data) = VolumeNode->dol_misc.dol_volume.dol_DiskType;

				D(("FSA_DOSTypeR = 0x%08lx", (*data)));

				break;

			case FSA_VersionNumberR:

				(*data) = (((ULONG)VERSION) << 16) | REVISION;

				D(("FSA_VersionNumberR = 0x%08lx", (*data)));

				break;

			case FSA_VersionStringR:

				length = GetTagData(FSA_VersionStringR_Len,0,args);

				D(("FSA_VersionStringR_Len = %ld", length));

				if(length > 0)
				{
					strlcpy((char *)data,VERS " (" DATE ")",length);
					D(("FSA_VersionStringR = \"%s\"", (char *)data));
				}

				break;

			case FSA_VersionStringR_Len:

				continue;

			case FSA_HasRecycledEntriesR:

				(*data) = FALSE;

				D(("FSA_HasRecycledEntriesR = %s", (*data) ? "TRUE" : "FALSE"));

				break;

			default:

				error = ERROR_NOT_IMPLEMENTED;
				goto out;
		}
	}

	result = DOSTRUE;

 out:

	(*error_ptr) = error;

	RETURN(result);
	return(result);
}

#endif /* ACTION_FILESYSTEM_ATTR */

/****************************************************************************/

static void
file_system_handler(
	BOOL			raise_priority,
	const TEXT *	device_name,
	const TEXT *	volume_name,
	const TEXT *	service_name)
{
	struct Process * this_process = (struct Process *)FindTask(NULL);
	BOOL check_for_netbios_keepalive = FALSE;
	BOOL sign_off = FALSE;
	int old_priority = 0;
	fd_set read_fds;
	int server_fd;
	ULONG signal_mask;
	ULONG signals;
	BOOL done;

	ENTER();

	display_error_message_list();

	if(NOT Quiet && WBStartup == NULL)
	{
		struct CommandLineInterface * cli;

		cli = Cli();

		if(NOT cli->cli_Background)
		{
			TEXT name[MAX_FILENAME_LEN+1];
			TEXT * dot;
			LONG max_cli;
			LONG which;
			LONG i;

			/* Figure out which CLI process number
			 * this command is associated with.
			 */
			Forbid();

			which = max_cli = MaxCli();

			for(i = 1 ; i <= max_cli ; i++)
			{
				if(FindCliProc(i) == this_process)
				{
					which = i;
					break;
				}
			}

			Permit();

			if(volume_name == NULL)
				strlcpy(name,device_name,sizeof(name));
			else
				strlcpy(name,volume_name,sizeof(name));

			/* If the device or volume name had a trailing
			 * colon character attached, remove it so that the
			 * output below will always show one colon
			 * character following the name, and not two.
			 */
			dot = (TEXT *)strchr(name, ':');
			if(dot != NULL)
				(*dot) = '\0';

			LocalFPrintf(ZERO, "Mounted '%s' as '%s:'; \"Break %ld\" or [Ctrl+C] to stop and unmount... ",
				service_name,name,which);

			Flush(Output());

			sign_off = TRUE;
		}
	}

	/* Don't show any further error message in the shell, and
	 * certainly don't allocate memory for error messages which
	 * would have to be displayed in an error requester (which
	 * doesn't happen).
	 */
	Quiet = TRUE;

	done = FALSE;

	if(raise_priority)
	{
		/* Raise the Task priority of the file system to 10
		 * unless it already is running at priority 10 or higher.
		 */
		Forbid();

		old_priority = this_process->pr_Task.tc_Node.ln_Pri;
		if(old_priority < 10)
			SetTaskPri((struct Task *)this_process, 10);

		Permit();
	}

	/* Check periodically for NetBIOS keep alive messages. */
	TimerRequest->tr_node.io_Command	= TR_ADDREQUEST;
	TimerRequest->tr_time.tv_secs		= 10;
	TimerRequest->tr_time.tv_micro		= 0;

	SendIO((struct IORequest *)TimerRequest);
	TimerTicking = TRUE;

	signal_mask = SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D | SIGBREAKF_CTRL_E | SIGBREAKF_CTRL_F | (1UL << FileSystemPort->mp_SigBit) | (1UL << TimerPort->mp_SigBit);

	FD_ZERO(&read_fds);

	do
	{
		/* If the server is currently connected, check if it has sent
		 * a NetBIOS "keep alive" message and deal with it.
		 */
		if(check_for_netbios_keepalive && (server_fd = ServerData->server.mount_data.fd) >= 0)
		{
			int n;

			/* We want to know if this socket has readable data for us. */
			FD_SET(server_fd, &read_fds);

			signals = signal_mask;

			/* Wait for the server to send something, a signal to be received
			 * or the next file system packet to arrive.
			 */
			PROFILE_OFF();

			n = WaitSelect(server_fd+1,&read_fds,NULL,NULL,NULL,&signals);

			PROFILE_ON();

			if(n > 0)
			{
				int num_bytes;
				UBYTE data[4];
				int error;

				/* We need to pick up everything that might be waiting to be
				 * read, but we need to stop reading from the socket as soon
				 * as there is no further data.
				 */
				while(TRUE)
				{
					/* Throw away what's waiting to be read. */
					num_bytes = smb_discard_netbios_frames(&ServerData->server, server_fd, &error);
					if(num_bytes != -1)
					{
						int non_blocking_io;

						SHOWMSG("checking for more data...");

						PROFILE_OFF();

						non_blocking_io = TRUE;
						IoctlSocket(server_fd, FIONBIO, &non_blocking_io);

						/* If there's what might be one NetBIOS header worth
						 * of data waiting to be read, keep going.
						 */
						num_bytes = recv(server_fd, data, sizeof(data), MSG_PEEK);
						if(num_bytes < 0)
							error = errno;

						non_blocking_io = FALSE;
						IoctlSocket(server_fd, FIONBIO, &non_blocking_io);

						PROFILE_ON();

						if(num_bytes > 0)
						{
							D(("there's probably something waiting to be read... (%ld bytes)", num_bytes));
							continue;
						}

						SHOWMSG("no more data's waiting");
					}

					/* If we ran into trouble we might want to shut down
					 * the server connection...
					 */
					if(num_bytes < 0 && error != EWOULDBLOCK)
					{
						D(("picked up trouble (error=%ld)",error));

						smb_check_server_connection(&ServerData->server, error);
					}

					SHOWMSG("and were'done here");
					break;
				}
			}

			D(("signals = 0x%08lx",signals));

			/* We don't want to call FD_ZERO() on each loop
			 * count because it is costly. This is why we
			 * clear the socket which we previously used on
			 * WaitSelect(), just in case the next loop
			 * iteration may end up changing the value of
			 * ServerData->server.mount_data.fd.
			 */
			FD_CLR(server_fd, &read_fds);

			check_for_netbios_keepalive = FALSE;

			TimerRequest->tr_node.io_Command	= TR_ADDREQUEST;
			TimerRequest->tr_time.tv_secs		= 10;
			TimerRequest->tr_time.tv_micro		= 0;

			SendIO((struct IORequest *)TimerRequest);
			TimerTicking = TRUE;
		}
		/* The server connection isn't ready yet, so we wait for
		 * stop/debug signals and more file system packets.
		 */
		else
		{
			PROFILE_OFF();

			signals = Wait(signal_mask);

			PROFILE_ON();
		}

		/* Schedule an NetBIOS keep alive check? */
		if(signals & (1UL << TimerPort->mp_SigBit))
		{
			SHOWMSG("scheduling a check for NetBIOS keep alive messages");

			WaitIO((struct IORequest *)TimerRequest);
			TimerTicking = FALSE;

			check_for_netbios_keepalive = TRUE;
		}

		/* Stop the file system? */
		if(signals & SIGBREAKF_CTRL_C)
		{
			SHOWMSG("stop signal received; trying to quit...");
			Quit = TRUE;
		}

		/* Re-enable the file system? If both disable and enable signals
		 * are present, we always stick with keeping the file system
		 * enabled.
		 */
		if (signals & SIGBREAKF_CTRL_E)
		{
			/* Note that the volume node needs to be around so that
			 * the Workbench and others can correctly report that
			 * the file system is not currently operational.
			 */
			if(VolumeNodeAdded && file_system_disabled)
			{
				SHOWMSG("re-enabling the file system");

				file_system_disabled = FALSE;

				send_disk_change_notification(IECLASS_DISKINSERTED);
			}
		}
		/* Disable the file system? */
		else if (signals & SIGBREAKF_CTRL_D)
		{
			if(VolumeNodeAdded && NOT file_system_disabled)
			{
				SHOWMSG("disabling the file system");

				file_system_disabled = TRUE;

				send_disk_change_notification(IECLASS_DISKREMOVED);
			}
		}

		if(signals & (1UL << FileSystemPort->mp_SigBit))
		{
			struct timeval start_time;
			struct DosPacket * dp;
			struct Message * mn;
			LONG res1,res2;

			while(TRUE)
			{
				/* Count the number of packets currently waiting to be processed. */
				#if DEBUG
				{
					ULONG num_packets_waiting;
					struct Node * ln;

					Disable();

					num_packets_waiting = 0;

					for(ln = FileSystemPort->mp_MsgList.lh_Head ;
					    ln->ln_Succ != NULL ;
					    ln = ln->ln_Succ)
					{
						num_packets_waiting++;
					}

					Enable();

					if (num_packets_waiting > 1)
						D(("%lu packets are waiting to be processed", num_packets_waiting));
					else if (num_packets_waiting == 1)
						SHOWMSG("1 packet is waiting to be processed");
					else
						SHOWMSG("no packet is waiting to be processed");
				}
				#endif /* DEBUG */

				mn = GetMsg(FileSystemPort);
				if(mn == NULL)
					break;

				dp = (struct DosPacket *)mn->mn_Node.ln_Name;

				#if DEBUG
				{
					/* We try to provide as much detail about the sender as
					 * possible.
					 */
					if((dp->dp_Port->mp_Flags & PF_ACTION) == PA_SIGNAL)
					{
						const struct Process * sender = (struct Process *)dp->dp_Port->mp_SigTask;

						/* Is this even a valid address? */
						if(sender == NULL || TypeOfMem((APTR)sender) == 0)
						{
							D(("got packet; sender 0x%08lx", (ULONG)sender));
						}
						/* Is the sender a Task? */
						else if (sender->pr_Task.tc_Node.ln_Type == NT_TASK)
						{
							D(("got packet; sender '%s' (Task)",((struct Node *)dp->dp_Port->mp_SigTask)->ln_Name));
						}
						/* Is this a Process with a CLI attached, e.g. a shell
						 * command may have sent this packet?
						 */
						else if (sender->pr_Task.tc_Node.ln_Type == NT_PROCESS && sender->pr_CLI != ZERO)
						{
							const struct CommandLineInterface * cli = BADDR(sender->pr_CLI);

							if (TypeOfMem((APTR)cli) != 0)
							{
								LONG cli_number = 0;
								LONG max_cli, i;
								TEXT command_name[256];

								/* Is this a known interactive shell or just
								 * a pointer which looks good enough?
								 */
								for(max_cli = MaxCli(), i = 1 ; i <= max_cli ; i++)
								{
									if (FindCliProc(i) == sender)
									{
										cli_number = i;
										break;
									}
								}

								/* Try to figure out the name of the shell
								 * command, if possible.
								 */
								if(cli->cli_Module != ZERO)
								{
									TEXT * cmd = BADDR(cli->cli_CommandName);
									int len;

									len = cmd[0];
									memcpy(command_name,&cmd[1],len);
									command_name[len] = '\0';
								}
								else
								{
									command_name[0] = '\0';
								}

								/* Is a this a shell command? */
								if(command_name[0] != '\0')
								{
									/* Is this a known interactive shell? */
									if(cli_number > 0)
										D(("got packet; sender '%s' (CLI #%ld)", command_name, cli_number));
									else
										D(("got packet; sender '%s' (CLI 0x%08lx)", command_name, (ULONG)cli));
								}
								/* No, it's just a shell. */
								else
								{
									D(("got packet; sender '%s' (CLI 0x%08lx)",((struct Node *)dp->dp_Port->mp_SigTask)->ln_Name, (ULONG)cli));
								}
							}
							/* Doesn't look like a valid CLI pointer. */
							else
							{
								D(("got packet; sender '%s' (Process)",((struct Node *)dp->dp_Port->mp_SigTask)->ln_Name));
							}
						}
						/* Just a process, no CLI. */
						else if (sender->pr_Task.tc_Node.ln_Type == NT_PROCESS)
						{
							D(("got packet; sender '%s' (Process)",((struct Node *)dp->dp_Port->mp_SigTask)->ln_Name));
						}
						/* Something else (hopefully). */
						else
						{
							D(("got packet; sender '%s'",((struct Node *)dp->dp_Port->mp_SigTask)->ln_Name));
						}
					}
					else
					{
						D(("got packet (MsgPort=0x%08lx)", (ULONG)dp->dp_Port));
					}
				}
				#endif /* DEBUG */

				/* We want to know how long it takes to process this packet. */
				#if DEBUG
				{
					GetSysTime((APTR)&start_time);
				}
				#endif /* DEBUG */

				res2 = 0;

				switch(dp->dp_Action)
				{
					case ACTION_DIE:

						SHOWMSG("ACTION_DIE");

						if(IsListEmpty((struct List *)&FileList) && IsListEmpty((struct List *)&LockList))
						{
							SHOWMSG("no locks or files pending; quitting");

							res1 = DOSTRUE;
						}
						else
						{
							SHOWMSG("locks or files still pending; cannot quit yet");

							res1 = DOSFALSE;
							res2 = ERROR_OBJECT_IN_USE;
						}

						Quit = TRUE;
						break;

					case ACTION_CURRENT_VOLUME:
						/* FileHandle->fh_Arg1 -> DeviceList, Unit */

						res1 = Action_CurrentVolume((struct FileNode *)dp->dp_Arg1,&res2);
						break;

					case ACTION_LOCATE_OBJECT:
						/* Lock,Name,Mode -> Lock */

						res1 = Action_LocateObject(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),BADDR(dp->dp_Arg2),dp->dp_Arg3,&res2);
						break;

					case ACTION_RENAME_DISK:
						/* Name -> Bool */

						res1 = Action_RenameDisk(BADDR(dp->dp_Arg1),&res2);
						break;

					case ACTION_FREE_LOCK:
						/* Lock -> Bool */

						res1 = Action_FreeLock((struct FileLock *)BADDR(dp->dp_Arg1),&res2);
						break;

					case ACTION_DELETE_OBJECT:
						/* Lock,Name -> Bool */

						res1 = Action_DeleteObject(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_RENAME_OBJECT:
						/* Source lock,source name,destination lock,destination name -> Bool */

						res1 = Action_RenameObject(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),BADDR(dp->dp_Arg2),
							(struct FileLock *)BADDR(dp->dp_Arg3),BADDR(dp->dp_Arg4),&res2);

						break;

					case ACTION_MORE_CACHE:
						/* Buffer delta -> Total number of buffers */

						/* Note: Documentation for this packet type is inconsistent;
						 *       in the 'good old' 1.x days 'res1' was documented as
						 *       the total number of buffers to be returned. In the
						 *       2.x documentation it is said that 'res1' should
						 *       return the success code, with 'res2' to hold the
						 *       total number of buffers.
						 *
						 *       However, the 'AddBuffers' shell command doesn't work
						 *       that way, and the dos.library implementation of
						 *       'AddBuffers()' doesn't work that way either.
						 *
						 *       The 1.3 'AddBuffers' command appears to treat a zero
						 *       result as failure and a non-zero result as success,
						 *       which suggests that this is how the packet is supposed
						 *       to work, contrary to what the official documentation
						 *       says.
						 */
						res1 = Action_MoreCache(dp->dp_Arg1,&res2);
						break;

					case ACTION_COPY_DIR:
						/* Lock -> Lock */

						res1 = Action_CopyDir(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),&res2);
						break;

					case ACTION_SET_PROTECT:
						/* (Ignore),Lock,Name,Mask -> Bool */

						res1 = Action_SetProtect(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg2),BADDR(dp->dp_Arg3),dp->dp_Arg4,&res2);
						break;

					case ACTION_CREATE_DIR:
						/* Lock,Name -> Lock */

						res1 = Action_CreateDir(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_EXAMINE_OBJECT:
						/* FileLock,FileInfoBlock -> Bool */

						res1 = Action_ExamineObject(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(struct FileInfoBlock *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_EXAMINE_NEXT:
						/* FileLock,FileInfoBlock -> Bool */

						res1 = Action_ExamineNext(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(struct FileInfoBlock *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_DISK_INFO:
						/* InfoData -> Bool */

						Action_DiskInfo((struct InfoData *)BADDR(dp->dp_Arg1),&res2);

						/* This should always work. */
						res1 = DOSTRUE;
						res2 = 0;

						break;

					case ACTION_INFO:
						/* FileLock,InfoData -> Bool */

						res1 = Action_Info(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(struct InfoData *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_SET_COMMENT:
						/* (Ignore),FileLock,Name,Comment -> Bool */

						res1 = Action_SetComment(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg2),BADDR(dp->dp_Arg3),BADDR(dp->dp_Arg4),&res2);
						break;

					case ACTION_PARENT:
						/* Lock -> Lock */

						res1 = Action_Parent(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),&res2);
						break;

					case ACTION_INHIBIT:

						SHOWMSG("ACTION_INHIBIT");

						res1 = DOSFALSE;
						res2 = ERROR_ACTION_NOT_KNOWN;

						break;

					case ACTION_SET_DATE:
						/* (Ignore),FileLock,Name,DateStamp(APTR) -> Bool */

						res1 = Action_SetDate(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg2),BADDR(dp->dp_Arg3),(struct DateStamp *)dp->dp_Arg4,&res2);
						break;

					case ACTION_SAME_LOCK:
						/* Lock,Lock -> Bool */

						res1 = Action_SameLock(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(struct FileLock *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_READ:
						/* FileHandle->fh_Arg1,Buffer(APTR),Length -> Length */

						res1 = Action_Read((struct FileNode *)dp->dp_Arg1,(APTR)dp->dp_Arg2,dp->dp_Arg3,&res2);
						break;

					case ACTION_WRITE:
						/* FileHandle->fh_Arg1,Buffer(APTR),Length -> Length */

						res1 = Action_Write((struct FileNode *)dp->dp_Arg1,(APTR)dp->dp_Arg2,dp->dp_Arg3,&res2);
						break;

					case ACTION_FINDUPDATE:
					case ACTION_FINDINPUT:
					case ACTION_FINDOUTPUT:
						/* FileHandle,FileLock,Name -> Bool */

						res1 = Action_Find(dp->dp_Port,dp->dp_Action,(struct FileHandle *)BADDR(dp->dp_Arg1),(struct FileLock *)BADDR(dp->dp_Arg2),BADDR(dp->dp_Arg3),&res2);
						break;

					case ACTION_END:
						/* FileHandle->fh_Arg1 -> Bool */

						res1 = Action_End((struct FileNode *)dp->dp_Arg1,&res2);
						break;

					case ACTION_SEEK:
						/* FileHandle->fh_Arg1,Position,Mode -> Position */

						res1 = Action_Seek((struct FileNode *)dp->dp_Arg1,dp->dp_Arg2,dp->dp_Arg3,&res2);
						break;

					case ACTION_SET_FILE_SIZE:
						/* FileHandle->fh_Arg1,Offset,Mode -> New file size */

						res1 = Action_SetFileSize((struct FileNode *)dp->dp_Arg1,dp->dp_Arg2,dp->dp_Arg3,&res2);
						break;

					case ACTION_WRITE_PROTECT:
						/* Flag,Key -> Bool */

						res1 = Action_WriteProtect(dp->dp_Arg1,dp->dp_Arg2,&res2);
						break;

					case ACTION_FH_FROM_LOCK:
						/* FileHandle(BPTR),FileLock -> Bool */

						res1 = Action_FHFromLock((struct FileHandle *)BADDR(dp->dp_Arg1),(struct FileLock *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_IS_FILESYSTEM:

						SHOWMSG("ACTION_IS_FILESYSTEM");
						res1 = DOSTRUE;
						break;

					case ACTION_CHANGE_MODE:
						/* Type,Object,Mode -> Bool */

						res1 = Action_ChangeMode(dp->dp_Port,dp->dp_Arg1,BADDR(dp->dp_Arg2),dp->dp_Arg3,&res2);
						break;

					case ACTION_COPY_DIR_FH:
						/* FileHandle->fh_Arg1 -> Bool */

						res1 = Action_CopyDirFH(dp->dp_Port,(struct FileNode *)dp->dp_Arg1,&res2);
						break;

					case ACTION_PARENT_FH:
						/* FileHandle->fh_Arg1 -> Bool */

						res1 = Action_ParentFH(dp->dp_Port,(struct FileNode *)dp->dp_Arg1,&res2);
						break;

					case ACTION_EXAMINE_ALL:
						/* FileLock,ExAllData(APTR),Size,Type,ExAllControl(APTR) -> Bool */

						/* Pretend that we do not support the ExAll() functionality? */
						if(DisableExAll)
						{
							res1 = DOSFALSE;
							res2 = ERROR_ACTION_NOT_KNOWN;
							break;
						}

						res1 = Action_ExamineAll(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(UBYTE *)dp->dp_Arg2,
							dp->dp_Arg3,dp->dp_Arg4,(struct ExAllControl *)dp->dp_Arg5,&res2);

						break;

					case ACTION_EXAMINE_FH:
						/* FileHandle->fh_Arg1,FileInfoBlock -> Bool */

						res1 = Action_ExamineFH((struct FileNode *)dp->dp_Arg1,(struct FileInfoBlock *)BADDR(dp->dp_Arg2),&res2);
						break;

					case ACTION_EXAMINE_ALL_END:
						/* FileLock,ExAllData(APTR),Size,Type,ExAllControl(APTR) -> Bool */

						res1 = Action_ExamineAllEnd(dp->dp_Port,(struct FileLock *)BADDR(dp->dp_Arg1),(UBYTE *)dp->dp_Arg2,
							dp->dp_Arg3,dp->dp_Arg4,(struct ExAllControl *)dp->dp_Arg5,&res2);

						break;

					case ACTION_LOCK_RECORD:
						/* FileHandle->fh_Arg1,position,length,mode,time-out -> Bool */

						res1 = Action_LockRecord((struct FileNode *)dp->dp_Arg1,dp->dp_Arg2,dp->dp_Arg3,dp->dp_Arg4,(ULONG)dp->dp_Arg5,&res2);
						break;

					case ACTION_FREE_RECORD:
						/* FileHandle->fh_Arg1,position,length -> Bool */

						res1 = Action_FreeRecord((struct FileNode *)dp->dp_Arg1,dp->dp_Arg2,dp->dp_Arg3,&res2);
						break;

					case ACTION_READ_LINK:

						/* Return -1 for ACTION_READ_LINK, for which DOSFALSE (= 0)
						 * would otherwise be a valid response. Bug fix contributed
						 * by Harry 'Piru' Sintonen.
						 */
						res1 = -1;
						res2 = ERROR_ACTION_NOT_KNOWN;
						break;

	#if defined(ACTION_FILESYSTEM_ATTR)

					case ACTION_FILESYSTEM_ATTR:

						res1 = Action_FilesystemAttr((struct TagItem *)dp->dp_Arg1,&res2);
						break;

	#endif /* ACTION_FILESYSTEM_ATTR */

					default:

						D(("Anything goes: dp->dp_Action=%ld (0x%lx)",dp->dp_Action,dp->dp_Action));

						res1 = DOSFALSE;
						res2 = ERROR_ACTION_NOT_KNOWN;
						break;
				}

				#if DEBUG
				{
					struct timeval finish_time;
					TEXT processing_time[30];

					/* Figure out how long it took to process this
					 * packet. Because the system time may have been
					 * adjusted between the beginning of the processing
					 * and getting here, we need to make sure that time
					 * didn't flow backwards...
					 */
					GetSysTime(&finish_time);

					if(-CmpTime(&finish_time,&start_time) >= 0)
					{
						int l;

						SubTime(&finish_time,&start_time);

						/* Print the processing time as the number of
						 * seconds which have passed, without trailing
						 * zeroes after the decimal point (and removing the
						 * decimal point altogether if all trailing zeroes
						 * have been removed.
						 */
						LocalSNPrintf(processing_time,sizeof(processing_time),"%lu.%06lu", finish_time.tv_secs, finish_time.tv_micro);

						l = strlen(processing_time);
						while(l > 0 && processing_time[l-1] == '0')
							l--;

						if(l > 0 && processing_time[l-1] == '.')
							l--;

						processing_time[l++] = 's';
						processing_time[l] = '\0';
					}
					else
					{
						strlcpy(processing_time,"unknown",sizeof(processing_time));
					}

					D(("Returning packet with res1=%ld (0x%08lx) and res2=%ld (0x%08lx); processing time=%s\n",res1,res1,res2,res2,processing_time));
				}
				#endif /* DEBUG */

				ReplyPkt(dp,res1,res2);
			}

			/* Let's get paranoid: check if we should quit. */
			if(SetSignal(0,0) & SIGBREAKF_CTRL_C)
			{
				SHOWMSG("stop signal received; trying to quit...");
				Quit = TRUE;

				break;
			}
		}

		#if DEBUG
		{
			if(signals & SIGBREAKF_CTRL_F)
			{
				struct FileNode * fn;
				struct LockNode * ln;

				SHOWMSG("list of open files:");

				for(fn = (struct FileNode *)FileList.mlh_Head ;
				    fn->fn_MinNode.mln_Succ != NULL ;
				    fn = (struct FileNode *)fn->fn_MinNode.mln_Succ)
				{
					D(("  name='%s'",escape_name(fn->fn_FullName)));
					D(("  mode=%ld, offset=%s",fn->fn_Mode,convert_quad_to_string(&fn->fn_OffsetQuad)));
					D((""));
				}

				SHOWMSG("list of allocated locks:");

				for(ln = (struct LockNode *)LockList.mlh_Head ;
				    ln->ln_MinNode.mln_Succ != NULL ;
				    ln = (struct LockNode *)ln->ln_MinNode.mln_Succ)
				{
					D(("  name='%s'",escape_name(ln->ln_FullName)));
					D(("  mode=%ld",ln->ln_FileLock.fl_Access));
					D((""));
				}
			}
		}
		#endif /* DEBUG */

		if(Quit)
		{
			if(IsListEmpty((struct List *)&FileList) && IsListEmpty((struct List *)&LockList))
			{
				SHOWMSG("no locks or files pending; quitting");
				done = TRUE;
			}
			else
			{
				SHOWMSG("locks or files still pending; cannot quit yet");
			}
		}
	}
	while(NOT done);

	if(raise_priority)
	{
		/* Restore the priority of the file system, unless the priority
		 * has already been changed.
		 */
		Forbid();

		if(old_priority < 10 && this_process->pr_Task.tc_Node.ln_Pri == 10)
			SetTaskPri((struct Task *)this_process, old_priority);

		Permit();
	}

	if(sign_off)
		LocalFPrintf(ZERO, "stopped.\n");

	LEAVE();
}

/****************************************************************************/

/* Convert an unsigned 64 bit integer into a string. The
 * conversion uses a local static buffer and returns a pointer
 * to the first digit of the string.
 */
const char *
convert_quad_to_string(const QUAD * number)
{
	static char string[22]; /* 21 bytes should be sufficient. */

	QUAD m = (*number);
	ULONG n;
	int len;

	memset(string,'\0',sizeof(string));

	for(len = sizeof(string) - 2 ; len >= 0 ; )
	{
		n = divide_64_by_32(&m,10,&m);

		string[len--] = '0' + n;

		if(m.High == 0 && m.Low == 0)
			break;
	}

	ASSERT( len+1 >= 0 );

	return(&string[len+1]);
}

/****************************************************************************/

/*
 * Copy src to string dst of size siz.	At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t result;

	/* Copy as many bytes as will fit */
	if(n != 0 && --n != 0)
	{
		do
		{
			if(((*d++) = (*s++)) == '\0')
				break;
		}
		while(--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if(n == 0)
	{
		if(siz != 0)
			(*d) = '\0';	/* NUL-terminate dst */

		while((*s++) != '\0')
			;
	}

	result = s - src - 1;	/* count does not include NUL */

	return(result);
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;
	size_t result;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while(n-- != 0 && (*d) != '\0')
		d++;

	dlen = d - dst;
	n = siz - dlen;

	if(n == 0)
	{
		result = dlen + strlen(s);
	}
	else
	{
		while((*s) != '\0')
		{
			if(n != 1)
			{
				(*d++) = (*s);
				n--;
			}

			s++;
		}

		(*d) = '\0';

		result = dlen + (s - src);	/* count does not include NUL */
	}

	return(result);
}
