/*
 * :ts=4
 *
 * proc.c
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 *
 * 28/06/96 - Fixed long file name support (smb_proc_readdir_long) by Yuri Per
 *
 * Modified for big endian support by Christian Starkjohann.
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#include "smbfs.h"
#include "quad_math.h"
#include "errors.h"

/*****************************************************************************/

#include <smb/smb.h>
#include <smb/smbno.h>
#include <smb/smb_fs.h>

/*****************************************************************************/

#include "smbfs_rev.h"

/*****************************************************************************/

/* smbfs uses the following commands:
 *
 * <smbno.h>		CIFS protocol documentation		Number	Protocol		Status		Purpose (-> Replacement)
 * SMBclose			SMB_COM_CLOSE					0x04	Core Protocol	-			close file
 * SMBcreate		SMB_COM_CREATE					0x03	Core Protocol	deprecated	create file (-> SMB_COM_NT_CREATE_ANDX)
 * SMBdskattr		SMB_COM_QUERY_INFORMATION_DISK	0x80	Core Protocol	deprecated	get disk attributes (-> SMB_COM_TRANSACTION2+TRANS2_QUERY_FS_INFORMATION)
 * SMBgetatr		SMB_COM_QUERY_INFORMATION		0x08	Core Protocol	deprecated	get file attributes (-> SMB_COM_TRANSACTION2+TRANS2_QUERY_PATH_INFORMATION)
 * SMBgetattrE		SMB_COM_QUERY_INFORMATION2		0x23	LAN Manager 1.0	deprecated	get file attributes expanded (-> SMB_COM_TRANSACTION2+TRANS2_QUERY_PATH_INFORMATION)
 * SMBlockingX		SMB_COM_LOCKING_ANDX			0x24	LAN Manager 1.0	-			lock/unlock byte ranges and X
 * SMBlseek			SMB_COM_SEEK					0x12	Core Protocol	obsolete	seek
 * SMBmkdir			SMB_COM_CREATE_DIRECTORY		0x00	Core Protocol	deprecated	create directory (-> SMB_COM_TRANSACTION2+TRANS2_CREATE_DIRECTORY)
 * SMBmv			SMB_COM_RENAME					0x07	Core Protocol	-			rename file
 * SMBnegprot		SMB_COM_NEGOTIATE				0x72	Core Protocol	-			negotiate protocol
 * SMBopen			SMB_COM_OPEN					0x02	Core Protocol	deprecated	open file (-> SMB_COM_NT_CREATE_ANDX)
 * SMBread			SMB_COM_READ					0x0A	Core Protocol	deprecated	read from file (-> SMB_COM_READ_ANDX)
 * SMBreadbraw		SMB_COM_READ_RAW				0x1a	Core Protocol	deprecated	read a block of data with no smb header (-> SMB_COM_READ_ANDX)
 * SMBreadX			SMB_COM_READ_ANDX				0x2E	LAN Manager 1.0	-			read and X
 * SMBrmdir			SMB_COM_DELETE_DIRECTORY		0x01	Core Protocol	-			delete directory
 * SMBsearch		SMB_COM_SEARCH					0x81	Core Protocol	deprecated	search directory (-> SMB_COM_TRANSACTION2+TRANS2_FIND_FIRST2)
 * SMBsesssetupX	SMB_COM_SESSION_SETUP_ANDX		0x73	LAN Manager 1.0	-			Session Set Up & X (including User Logon)
 * SMBsetatr		SMB_COM_SET_INFORMATION			0x09	Core Protocol	deprecated	set file attributes (-> SMB_COM_TRANSACTION2+TRANS2_SET_PATH_INFORMATION)
 * SMBsetattrE		SMB_COM_SET_INFORMATION2		0x22	LAN Manager 1.0	deprecated	set file attributes expanded (-> SMB_COM_TRANSACTION2+TRANS2_SET_PATH_INFORMATION)
 * SMBtcon			SMB_COM_TREE_CONNECT			0x70	Core Protocol	deprecated	tree connect (-> SMB_COM_TREE_CONNECT_ANDX)
 * SMBtconX			SMB_COM_TREE_CONNECT_ANDX		0x75	LAN Manager 1.0	-			tree connect and X
 * SMBtrans2		SMB_COM_TRANSACTION2			0x32	LAN Manager 1.2	-			TRANS2 protocol set
 * SMBunlink		SMB_COM_DELETE					0x06	Core Protocol	-			delete file
 * SMBwrite			SMB_COM_WRITE					0x0B	Core Protocol	deprecated	write to file (-> SMB_COM_WRITE_ANDX)
 * SMBwritebraw		SMB_COM_WRITE_RAW				0x1d	LAN Manager 1.0	deprecated	write a block of data with no smb header (-> SMB_COM_WRITE_ANDX)
 * SMBwriteX		SMB_COM_WRITE_ANDX				0x2F	LAN Manager 1.0	-			write and X
 */

/*****************************************************************************/

/* Byte offsets into the packet buffer reference the following data
 * (with the first four octets used by the NetBIOS session header):
 *
 *  0:	WORD netbios_session[2]	= NetBIOS session header
 *  4:	BYTE smb_idf[4]			= contains 0xFF, 'SMB'
 *  8:	BYTE smb_com			= command code
 *  9:	BYTE smb_rcls			= error code class
 * 10:	BYTE smb_reh			= reserved (contains AH if DOS INT-24 ERR)
 * 11:	WORD smb_err			= error code
 * 13:	BYTE smb_reb			= reserved
 * 14:	WORD smb_res[7]			= reserved
 * 28:	WORD smb_tid			= tree id #
 * 30:	WORD smb_pid			= caller's process id #
 * 32:	WORD smb_uid			= user id #
 * 34:	WORD smb_mid			= mutiplex id #
 * 36:	BYTE smb_wct			= count of parameter words
 * 37:	WORD smb_vwv[]			= variable # words of params
 * 39:	WORD smb_bcc			= # bytes of data following
 * 41:	BYTE smb_data[]			= data bytes
 */

#define SMB_VWV(packet)		(&(packet)[37])
#define SMB_CMD(packet)		((packet)[8])
#define SMB_WCT(packet)		((packet)[36])
#define SMB_BCC(packet)		smb_bcc(packet)
#define SMB_BUF(packet)		((packet) + 37 + SMB_WCT(packet) * sizeof(word) + sizeof(word))

/*****************************************************************************/

#define SMB_DIRINFO_SIZE	43
#define SMB_RESUME_KEY_SIZE	21

/*****************************************************************************/

/* Some message size calculations include the size of the NetBIOS session
 * header, which may not be necessary. The "message size" in question is not
 * the same as the underlying transport layer, which in this case is
 * NetBIOS over TCP.
 */
#define NETBIOS_HEADER_SIZE 4

/*****************************************************************************/

/* This is for testing if the message exchange still works if the
 * server claims to accept less than 65535 bytes per message.
 */
/*#define OVERRIDE_SERVER_MAX_BUFFER_SIZE 16644*/

/*****************************************************************************/

static void smb_printerr(int class, int num);
static int smb_proc_reconnect (struct smb_server *server, int * error_ptr);

/*****************************************************************************/

/* error code stuff - put together by Merik Karman
 * merik -at- blackadder -dot- dsh -dot- oz -dot- au
 */
typedef struct
{
	const char *	name;
	int				code;
	const char *	message;
} err_code_struct;

/* Dos Error Messages */
static const err_code_struct dos_msgs[] =
{
	{"ERRbadfunc",					1,		"Invalid function"},
	{"ERRbadfile",					2,		"File not found"},
	{"ERRbadpath",					3,		"Directory invalid"},
	{"ERRnofids",					4,		"No file descriptors available"},
	{"ERRnoaccess",					5,		"Access denied"},
	{"ERRbadfid",					6,		"Invalid file handle"},
	{"ERRbadmcb",					7,		"Memory control blocks destroyed"},
	{"ERRnomem",					8,		"Insufficient server memory to perform the requested function"},
	{"ERRbadmem",					9,		"Invalid memory block address"},
	{"ERRbadenv",					10,		"Invalid environment"},
	{"ERRbadformat",				11,		"Invalid format"},
	{"ERRbadaccess",				12,		"Invalid open mode"},
	{"ERRbaddata",					13,		"Invalid data"},
	{"ERR",							14,		"reserved"},
	{"ERRbaddrive",					15,		"Invalid drive specified"},
	{"ERRremcd",					16,		"A Delete Directory request attempted to remove the server's current directory"},
	{"ERRdiffdevice",				17,		"Not same device"},
	{"ERRnofiles",					18,		"A File Search command can find no more files matching the specified criteria"},
	{"ERRbadshare",					32,		"The sharing mode specified for an Open conflicts with existing FIDs on the file"},
	{"ERRlock",						33,		"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process"},
	{"ERRnosuchshare",				67,		"Share name not found"},
	{"ERRfilexists",				80,		"The file named in a Create Directory, Make New File or Link request already exists"},
	{"ERRpaused",					81,		"The server is temporarily paused"},
	{"ERRinvalidparam",				87,		"One of the requested values is out of range"},
	{"ERRtimeout",					88,		"The requested operation on a named pipe or an I/O device has timed out"},
	{"ERRnoresource",				89,		"No resources currently available for this SMB request"},
	{"ERRtoomanyuids",				90,		"Too many UIDs active for this SMB connection"},
	{"ERRbaduid",					91,		"The UID supplied is not known to the session, or the user identified by the UID does not have sufficient privileges"},
	{"ERROR_DIRECTORY_NOT_EMPTY",	145,	"The directory is not empty"},
	{"OBJECT_NAME_COLLISION",		183,	"Object name collision"},
	{"ERRinvalidname",				123,	"Invalid name"},
	{"ERRbadpipe",					230,	"Pipe invalid"},
	{"ERRpipebusy",					231,	"All instances of the requested pipe are busy"},
	{"ERRpipeclosing",				232,	"Pipe close in progress"},
	{"ERRnotconnected",				233,	"No process on other end of pipe"},
	{"ERRmoredata",					234,	"There is more data to be returned"},
	{"ERROR_EAS_DIDNT_FIT",			275,	"Either there are no extended attributes, or the available extended attributes did not fit into the response"},
	{"ERROR_EAS_NOT_SUPPORTED",		282,	"The server file system does not support Extended Attributes"},

	{NULL, -1, NULL}
};

/* Server Error Messages */
static const err_code_struct server_msgs[] =
{
	{"ERRerror",			1,		"Non-specific error code"},
	{"ERRbadpw",			2,		"Bad password - name/password pair in a Tree Connect or Session Setup are invalid"},
	{"ERRbadtype",			3,		"reserved"},
	{"ERRaccess",			4,		"The requester does not have the necessary access rights within the specified context for the requested function. The context is defined by the TID or the UID"},
	{"ERRinvnid",			5,		"The tree ID (TID) specified in a command was invalid"},
	{"ERRinvnetname",		6,		"Invalid network name in tree connect"},
	{"ERRinvdevice",		7,		"Invalid device - printer request made to non-printer connection or non-printer request made to printer connection"},
	{"ERRqfull",			49,		"Print queue full (files) -- returned by open print file"},
	{"ERRqtoobig",			50,		"Print queue full -- no space"},
	{"ERRqeof",				51,		"EOF on print queue dump"},
	{"ERRinvpfid",			52,		"Invalid print file FID"},
	{"ERRsmbcmd",			64,		"The server did not recognize the command received"},
	{"ERRsrverror",			65,		"The server encountered an internal error, e.g., system file unavailable"},
	{"ERRfilespecs",		67,		"The file handle (FID) and pathname parameters contained an invalid combination of values"},
	{"ERRreserved",			68,		"reserved"},
	{"ERRbadpermits",		69,		"The access permissions specified for a file or directory are not a valid combination. The server cannot set the requested attribute"},
	{"ERRreserved",			70,		"reserved"},
	{"ERRsetattrmode",		71,		"The attribute mode in the Set File Attribute request is invalid"},
	{"ERRpaused",			81,		"Server is paused"},
	{"ERRmsgoff",			82,		"Not receiving messages"},
	{"ERRnoroom",			83,		"No room to buffer message"},
	{"ERRrmuns",			87,		"Too many remote user names"},
	{"ERRtimeout",			88,		"Operation timed out"},
	{"ERRnoresource",		89,		"No resources currently available for request"},
	{"ERRtoomanyuids",		90,		"Too many UIDs active on this session"},
	{"ERRbaduid",			91,		"The UID is not known as a valid ID on this session"},
	{"ERRusempx",			250,	"Temp unable to support Raw, use MPX mode"},
	{"ERRusestd",			251,	"Temp unable to support Raw, use standard read/write"},
	{"ERRcontmpx",			252,	"Continue in MPX mode"},
	{"ERRreserved",			253,	"reserved"},
	{"ERRbadPW",			254,	"Invalid password"},
	{"ERRaccountExpired",	2239,	"User account on the target machine is disabled or has expired"},
	{"ERRbadClient",		2240,	"The client does not have permission to access this server"},
	{"ERRbadLogonTime",		2241,	"Access to the server is not permitted at this time"},
	{"ERRpasswordExpired",	2242,	"The user's password has expired"},
	{"ERRnosupport",		0xFFFF,	"Function not supported"},

	{NULL, -1, NULL}
};

/* Hard Error Messages */
static const err_code_struct hard_msgs[] =
{
	{"ERRnowrite",		19,	"Attempt to write on write-protected diskette"},
	{"ERRbadunit",		20,	"Unknown unit"},
	{"ERRnotready",		21,	"Drive not ready"},
	{"ERRbadcmd",		22,	"Unknown command"},
	{"ERRdata",			23,	"A problem has occured in the physical I/O"},
	{"ERRbadreq",		24,	"Bad request structure length"},
	{"ERRseek",			25,	"Seek error"},
	{"ERRbadmedia",		26,	"Unknown media type"},
	{"ERRbadsector",	27,	"Sector not found"},
	{"ERRnopaper",		28,	"Printer out of paper"},
	{"ERRwrite",		29,	"Write fault"},
	{"ERRread",			30,	"Read fault"},
	{"ERRgeneral",		31,	"General failure"},
	{"ERRbadshare",		32,	"A open conflicts with an existing open"},
	{"ERRlock",			33,	"A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process"},
	{"ERRwrongdisk",	34,	"The wrong disk was found in a drive"},
	{"ERRFCBUnavail",	35,	"No FCBs are available to process request"},
	{"ERRsharebufexc",	36,	"A sharing buffer has been exceeded"},
	{"ERRdiskfull",		39,	"The file system is full"},

	{NULL, -1, NULL}
};

typedef struct
{
	int						code;
	const char *			class;
	const err_code_struct *	err_msgs;
} err_class_struct;

static const err_class_struct err_classes[] =
{
	{ 0,	"SUCCESS",	NULL },
	{ 0x01,	"ERRDOS",	dos_msgs },
	{ 0x02,	"ERRSRV",	server_msgs },
	{ 0x03,	"ERRHRD",	hard_msgs },
	{ 0x04,	"ERRXOS",	NULL },
	{ 0xE1,	"ERRRMX1",	NULL },
	{ 0xE2,	"ERRRMX2",	NULL },
	{ 0xE3,	"ERRRMX3",	NULL },
	{ 0xFF,	"ERRCMD",	NULL },

	{ -1, NULL, NULL }
};

/*****************************************************************************/

static time_t convert_long_date_to_time_t(const char * p);
static void convert_time_t_to_long_date(time_t t, QUAD * long_date);

/*****************************************************************************/

static int
size_utf16le_of_latin1(const struct smb_server *server, const byte *from)
{
	const byte* from1;
	int latin1_part_size;

	from1 = strrchr(from, '\\');
	from1++;

	latin1_part_size = (from1 - from) * 2; // * 2 because UTF16

	if(NULL != kvs_get_value(server->latin1_to_utf16le_bytes, from1))
	{
		// report_error("%s is in store! (1)", from1);
		return latin1_part_size + atoi(kvs_get_value(server->latin1_to_utf16le_sizes, from1));
	}
	else
	{
		return -1;
	}
}

/* Copy a string in ISO-Latin-1 form (8 bits per character) into a
 * buffer, converting it into a little-endian 16 bit Unicode version
 * of the string. This works because the ISO-Latin-1 character sits
 * within the ASCII/BMP Latin-1 Unicode range.
 *
 * This function creates a NUL-terminated UTF16-LE Unicode string and
 * returns how many bytes were written to the buffer, including the
 * null-termination.
 *
 * To be on the safe side (the path name length can be a 32 bit
 * integer), the whole copying operation stops as soon as the
 * output buffer is filled.
 */
static int
copy_latin1_to_utf16le(const struct smb_server *server, byte * to,int to_size, const byte * from,int len)
{
	int num_bytes_written = 0;
	int i;

	// Tygre 21/05/15: Asymmetry
	// The arguments of this function are not symetrical
	// with those of copy_utf16le_to_latin1(). While in
	// copy_utf16le_to_latin1(), the "from" represents
	// a single part of a path, i.e., "toto". Here, the
	// "from" includes the whole path, i.e., "a\b\toto".
	//
	// Right now, I *ASSUME* that only the file name,
	// i.e., the last part of the path, can be non-Latin1.
	// I replace this last part with the stored original
	// UTF16le name if it exists.
	const byte* from1;
	long  id_l;
	char* id_s;
	BOOL  is_stored;

	from1 = strrchr(from, '\\');
	from1++;
	id_s = malloc(11);
	if(NULL == id_s)
	{
		return -1;
	}
	is_stored  = FALSE;

	if(NULL != kvs_get_value(server->latin1_to_utf16le_bytes, from1))
	{
		// report_error("%s is in store! (2)", from1);
		is_stored = TRUE;
		len = len - strlen(from1);
	}

	/* We have to have enough room to NUL-terminate the
	 * resulting converted string.
	 */
	if(to_size >= 2)
	{
		/* That takes care of the NUL. */
		to_size -= 2;

		for(i = 0 ; i < len ; i++)
		{
			if(num_bytes_written + 2 > to_size)
				break;

			(*to++) = (*from++);
			(*to++) = '\0';

			num_bytes_written += 2;
		}

		// Tygre 21/05/15: Stored UTF16le
		if(is_stored)
		{
			/* No needdd to take care of the NUL. */
			to_size += 2;

			/* We already wrote some bytes */
			to_size -= num_bytes_written;

			
			id_l = atoi(kvs_get_value(server->latin1_to_utf16le_sizes, from1));
			// sprintf(id_s, "%ld", id_l);
			// report_error("Retrieving %s bytes for %s", id_s, from1);
			// sprintf(id_s, "%ld", to_size);
			// report_error("To be copied in %s bytes", id_s);
			if(id_l > to_size)
			{
				report_error("Cannot copy all bytes for lack of space!");
			}
			else if(id_l < to_size)
			{
				report_error("Cannot fill in all space!");
			}

			memcpy(
				to,
				kvs_get_value(server->latin1_to_utf16le_bytes, from1),
				to_size);
			
			num_bytes_written += to_size;
		}
		else
		{
			/* And we terminate that string... */
			(*to++)	= '\0';
			(*to)	= '\0';
			
			num_bytes_written += 2;
		}
	}

	return(num_bytes_written);
}

/*****************************************************************************/

/* Copy a string in little-endian 16 bit Unicode into a buffer, converting
 * it into a ISO-Latin-1 (8 bits per character) version of the string, if
 * possible. Code points beyond the ASCII/BMP Latin-1 character set are
 * replaced by the control character 0x80.
 *
 * Note that the length is given as the number of 16 bit Unicode
 * characters, not the number of bytes required to store the string.
 *
 * This function creates a NUL-terminated ISO-Latin-1 string and
 * returns how many bytes were written to the buffer, including the
 * null-termination.
 *
 * To be on the safe side (the path name length can be a 32 bit
 * integer), the whole copying operation stops as soon as the
 * output buffer is filled.
 */
static int
copy_utf16le_to_latin1(const struct smb_server *server, byte * to, int to_size, const byte * from, int len)
{
	int num_bytes_written = 0;
	word c;
	int i, j;

	// Tygre 21/05/08: Encoding of non-Latin1 names
	// The maximum number of chars for representing a long is 10 on 32-bit computers (2147483647)
	#define LONG_MAX_CHARS 10
	// The maximum number of chars for a file name in OFS
	#define MAX_SIZE 31
	const byte* from1;
	byte* from1_copy;
	byte* to1;
	long  tmp_l;
	byte* tmp_s;
	long  id_l;
	char* id_s;
	BOOL  should_store;
	char  tmp[MAX_SIZE];
	
	from1 = from;
	to1 = to;
	id_s = malloc(LONG_MAX_CHARS + 1); // LONG_MAX_CHARS plus NUL
	if(NULL == id_s)
	{
		return -1;
	}

	/* We have to have enough room to NUL-terminate the
	 * resulting converted string.
	 */
	if(to_size >= 1)
	{
		/* That takes care of the NUL. */
		to_size -= 1;

		for(i = 0, id_l = 0, should_store = FALSE; i < len ; i++, from += 2)
		{
			if(num_bytes_written + 1 > to_size)
				break;

			/* Pick up the next UTF-16 code point,
			 * and just hopefully it will map to
			 * exactly one ASCII/BMP Latin-1
			 * character. If not, we substitute it
			 * with an "unusable" character which
			 * will be detected later, resulting in
			 * the file/directory name to be
			 * dropped.
			 */
			c = ((word)from[1] << 8) | from[0];
			if(c >= 256)
			{
				// Tygre 21/05/08: Encoding
				// Replace non-Latin1 chars by 'X'
				// and sum up their values to make
				// up an encoding.
				should_store = TRUE;
				id_l += c;
				(*to++) = 'X';
				num_bytes_written++;
			}
			else
			{
				id_l += c;
				(*to++) = c;
				num_bytes_written++;
			}
		}

		/* And we terminate that string... */
		(*to) = '\0';
		num_bytes_written++;

		// Tygre 21/05/08: Encoding of non-Latin1 names
		// I can memmove happily because to_size is always 255
		// and thus greater than the longest file name (107)
		// and the dozen chars that I add.
		// Tested with six files whose names are (with X for non-Latin1 chars):
		//	- <40 chars>
		//	- <40 chars>.txt
		//	- <40 chars>.<40 chars>
		//	- <5 chars>
		//	- <5 chars>.txt
		//	- <5 chars>.<40 chars>
		if(should_store)
		{
			// 1. Replace non-Latin1 names with a unique (?) number
			// TOO SIMPLISTIC
			/*
			sprintf(id_s, "%0*ld", LONG_MAX_CHARS, id_l);
			memmove(to1, id_s, LONG_MAX_CHARS + 1);
			num_bytes_written = LONG_MAX_CHARS + 1;
			*/

			// 2. Replace non-Latin1 names with a unique (?) number and add extension
			// BETTER BUT WHAT IF EXTENSION IS LOOONG?
			/*
			if(tmp_s = strrchr(to1, '.'))
			{
				tmp_l = strlen(tmp_s);
				memmove(to1 + LONG_MAX_CHARS, tmp_s, tmp_l + 1); // "+ 1" to include the NUL
			}
			else
			{
				tmp_l = 0;
				(*(to1 + LONG_MAX_CHARS)) = '\0';
			}
			sprintf(id_s, "%0*ld", LONG_MAX_CHARS, id_l);
			memmove(to1, id_s, LONG_MAX_CHARS);
			num_bytes_written = LONG_MAX_CHARS + tmp_l + 1;
			*/

			// 3. Prefix non-Latin1 names with unique (?) number
			// WHAT ABOUT FILE NAMES GREATER THAN A LIMIT? (31 or 107...)
			/*
			sprintf(id_s, "%0*ld", LONG_MAX_CHARS, id_l);
			if(num_bytes_written > to_size - LONG_MAX_CHARS - 1)
			{
				num_bytes_written = num_bytes_written - (to_size - LONG_MAX_CHARS - 1 - num_bytes_written);
			}
			memmove(to1 + (LONG_MAX_CHARS + 1), to1,  num_bytes_written);
			memmove(to1,      id_s, LONG_MAX_CHARS);
			(*(to1 + LONG_MAX_CHARS)) = ' ';
			to = to + (LONG_MAX_CHARS + 1);
			(*to) = '\0';
			num_bytes_written += (LONG_MAX_CHARS + 1);
			*/

			// 4. Postfix, before any '.', non-Latin1 names with unique (?) number
			// WHAT ABOUT FILE NAMES GREATER THAN A LIMIT? (31 or 107...)
			/*
			sprintf(id_s, "%0*ld", LONG_MAX_CHARS, id_l);
			if(NULL != (tmp = strrchr(to1, '.')))
			{
				memmove(tmp + (LONG_MAX_CHARS + 1), tmp, strlen(tmp) + 1); // + 1 to include the NUL
				to = tmp;
			}
			(*to++) = ' ';
			memmove(to, id_s, LONG_MAX_CHARS);
			to += LONG_MAX_CHARS;
			num_bytes_written += strlen(to1) + 1;
			*/

			// 5. Keep as many chars of the extension as possible (with Xs for non-Latin1 chars).
			// Insert the unique ID before the extension, the ID is always LONG_MAX_CHARS long.
			// Keep as many chars of the original name (with Xs for non-Latin1 chars).
			/*
			#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
			#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
			if(tmp_s = strrchr(to1, '.'))
			{
				tmp_l = strlen(tmp_s);
				if(tmp_l > MAX_SIZE - 1 - LONG_MAX_CHARS - 1)
				{
					j = MAX_SIZE - 1 - LONG_MAX_CHARS - 1;
					sprintf(tmp, "@%0*ld%.*s", LONG_MAX_CHARS, id_l, j, tmp_s);
				}
				else
				{
					j = tmp_l;
					tmp_l = strlen(to1) - j;
					i = MIN(tmp_l, MAX_SIZE - j - 1 - 1 - LONG_MAX_CHARS - 1);
					sprintf(tmp, "%.*s @%0*ld%.*s", i, to1, LONG_MAX_CHARS, id_l, j, tmp_s);
				}
			}
			else
			{
				tmp_l = strlen(to1);
				i = MIN(tmp_l, MAX_SIZE - 1 - 1 - LONG_MAX_CHARS - 1);
				sprintf(tmp, "%.*s @%0*ld", i, LONG_MAX_CHARS, id_l);
			}
			memmove(to1, tmp, tmp_l + 1);
			num_bytes_written = tmp_l + 1;
			*/


			// 6. Keep as many chars of the extension as possible (with Xs for non-Latin1 chars).
			// Insert the unique ID before the extension, as long as need but no longer.
			// Keep as many chars of the original name (with Xs for non-Latin1 chars).
			#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
			#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))
			sprintf(id_s, "%ld", id_l);
			if(tmp_s = strrchr(to1, '.'))
			{
				tmp_l = strlen(tmp_s);
				if(tmp_l > MAX_SIZE - 1 - strlen(id_s) - 1)
				{
					j = MAX_SIZE - 1 - strlen(id_s) - 1;
					tmp_l = sprintf(tmp, "@%s%.*s", id_s, j, tmp_s);
				}
				else
				{
					j = tmp_l;
					tmp_l = strlen(to1) - j;
					i = strlen(id_s);
					i = MIN(tmp_l, MAX_SIZE - j - 1 - 1 - i - 1);
					tmp_l = sprintf(tmp, "%.*s @%s%.*s", i, to1, id_s, j, tmp_s);
				}
			}
			else
			{
				tmp_l = strlen(to1);
				i = strlen(id_s);
				i = MIN(tmp_l, MAX_SIZE - 1 - 1 - i - 1);
				tmp_l = sprintf(tmp, "%.*s @%s", i, to1, id_s);
			}
			memmove(to1, tmp, tmp_l + 1);
			num_bytes_written = tmp_l + 1;

			// If the bytes and their sizes are not already in store
			if(NULL == kvs_get_value(server->latin1_to_utf16le_bytes, to1))
			{
				id_l = len * 2;            // "* 2" because each UTF16 char takes 2 bytes
				from1_copy = malloc(id_l); // Make a copy of "from" of length "len"
				if(NULL == from1_copy)
				{
					return -1;
				}
				memcpy(from1_copy, from1, id_l);
				kvs_put(server->latin1_to_utf16le_bytes, to1, from1_copy);

				sprintf(id_s, "%ld", id_l);
				kvs_put(server->latin1_to_utf16le_sizes, to1, id_s);
			}
		}
	}

	return(num_bytes_written);
}

/*****************************************************************************/

#define strnlen local_strnlen

/* Works just like strlen(), but stops as soon as it hits
 * the boundaries of the buffer which contains the string.
 */
static size_t strnlen(const char * s,size_t max_size)
{
	const char * start = s;
	size_t result;

	if(max_size > 0)
	{
		while((*s) != '\0' && max_size-- > 0)
			s++;
	}

	result = (size_t)(s - start);

	return(result);
}

/*****************************************************************************/

/* Works just like strnlen(), but operates on 16 bit characters. */
static size_t strnlen_utf16(const char * s,size_t max_size)
{
	size_t result = 0;

	while(max_size >= 2)
	{
		if((s[0] | s[1]) == 0)
			break;

		s += 2;
		max_size -= 2;

		result++;
	}

	return(result);
}

/*****************************************************************************/

/*****************************************************************************
 *
 *  Encoding/Decoding section
 *
 *****************************************************************************/
static INLINE byte *
smb_encode_byte(byte * p, byte data)
{
	(*p) = data;
	return &p[1];
}

static INLINE byte *
smb_encode_word (byte * p, word data)
{
	p[0] = data & 0x00ffU;
	p[1] = (data & 0xff00U) >> 8;
	return &p[2];
}

static INLINE byte *
smb_encode_dword (byte * p, dword data)
{
	p[0] = data & 0xffU;
	p[1] = (data & 0xff00U) >> 8;
	p[2] = (data & 0xff0000U) >> 16;
	p[3] = (data & 0xff000000U) >> 24;
	return &p[4];
}

static byte *
smb_copy_data (byte * p, const byte * data, int len)
{
	memmove (p, data, len);
	return &p[len];
}

static INLINE byte *
smb_decode_word (const byte * p, word * data)
{
	(*data) = ((word)p[0]) | (((word)p[1]) << 8);

	return (byte *)&p[2];
}

static INLINE byte *
smb_decode_dword (const byte * p, dword * data)
{
	(*data) = ((dword)p[0]) | (((dword)p[1]) << 8) | (((dword)p[2]) << 16) | (((dword)p[3]) << 24);

	return (byte *)&p[4];
}

static INLINE byte *
smb_encode_smb_length (byte * p, int len)
{
	/* 0x00 = NetBIOS session message */
	p[0] = 0;

	/* Length is a 17 bit integer, the most significant
	 * bit of which goes into bit #0. The other 7 bits
	 * are reserved.
	 */
	p[1] = (len >> 16) & 1;

	/* Payload length in network byte order
	 * (least significant 16 bits).
	 */
	p[2] = (len & 0xFF00) >> 8;
	p[3] = (len & 0xFF);

	return &p[4];
}

static byte *
smb_encode_dialect (byte * p, const byte * name, int len)
{
	(*p++) = 2;

	memcpy(p, name, len);
	p[len] = '\0';

	return p + len + 1;
}

static byte *
smb_encode_ascii (byte * p, const byte * name, int len)
{
	(*p++) = 4; /* A NUL-terminated string follows. */

	memcpy (p, name, len);
	p[len] = '\0';

	return p + len + 1;
}

static void
smb_encode_vblock (byte * p, const byte * data, int len)
{
	ASSERT( 0 <= len && len <= 65535 );

	(*p++) = 5; /* a variable block is to follow. */
	p = smb_encode_word (p, len);
	memcpy (p, data, len);
}

static byte *
smb_name_mangle (byte * p, const byte * name)
{
	int len, pad = 0;

	len = strlen (name);

	if (len < 16)
		pad = 16 - len;

	(*p++) = 2 * (len + pad);

	while ((*name) != '\0')
	{
		(*p++) = ((*name) >> 4) + 'A';
		(*p++) = ((*name) & 0x0F) + 'A';

		name++;
	}

	while (pad-- > 0)
	{
		(*p++) = 'C';
		(*p++) = 'A';
	}

	(*p++) = '\0';

	return p;
}

/* According to the core protocol documentation times are
 * expressed as seconds past January 1st, 1970, local
 * time zone.
 */
static int
utc2local (int time_value)
{
	int result;

	if(time_value > 0)
		result = time_value - get_time_zone_delta();
	else
		result = time_value;

	return result;
}

static int
local2utc (int time_value)
{
	int result;

	if(time_value > 0)
		result = time_value + get_time_zone_delta();
	else
		result = time_value;

	return result;
}

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since January 1st 1970). */
static int
date_dos2unix (unsigned short time_value, unsigned short date)
{
	time_t seconds;
	time_t utc_seconds;
	struct tm tm;

	memset(&tm,0,sizeof(tm));

	tm.tm_sec	= 2 * (time_value & 0x1F);
	tm.tm_min	= (time_value >> 5) & 0x3F;
	tm.tm_hour	= (time_value >> 11) & 0x1F;
	tm.tm_mday	= date & 0x1F;
	tm.tm_mon	= ((date >> 5) & 0xF) - 1;
	tm.tm_year	= ((date >> 9) & 0x7F) + 80;

	seconds = tm_to_seconds(&tm);

	utc_seconds = local2utc(seconds);

	#if DEBUG
	{
		struct tm tm_utc;
		struct tm tm_local;

		seconds_to_tm(utc_seconds,&tm_utc);

		D(("time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
			tm_utc.tm_year + 1900,
			tm_utc.tm_mon+1,
			tm_utc.tm_mday,
			tm_utc.tm_hour,
			tm_utc.tm_min,
			tm_utc.tm_sec));

		seconds_to_tm(seconds,&tm_local);

		D(("       %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
			tm_local.tm_year + 1900,
			tm_local.tm_mon+1,
			tm_local.tm_mday,
			tm_local.tm_hour,
			tm_local.tm_min,
			tm_local.tm_sec));
	}
	#endif /* DEBUG */

	return(utc_seconds);
}

/* Convert linear UNIX date to a MS-DOS time/date pair. */
static void
date_unix2dos (int utc_seconds, unsigned short *time_value, unsigned short *date)
{
	time_t seconds;
	struct tm tm;

	seconds = utc2local(utc_seconds);

	seconds_to_tm(seconds,&tm);

	#if DEBUG
	{
		struct tm tm_utc;
		struct tm tm_local;

		seconds_to_tm(utc_seconds,&tm_utc);

		D(("time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
			tm_utc.tm_year + 1900,
			tm_utc.tm_mon+1,
			tm_utc.tm_mday,
			tm_utc.tm_hour,
			tm_utc.tm_min,
			tm_utc.tm_sec));

		seconds_to_tm(seconds,&tm_local);

		D(("       %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
			tm_local.tm_year + 1900,
			tm_local.tm_mon+1,
			tm_local.tm_mday,
			tm_local.tm_hour,
			tm_local.tm_min,
			tm_local.tm_sec));
	}
	#endif /* DEBUG */

	(*time_value) = (tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2);
	(*date) = ((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday;
}

/****************************************************************************
 *
 *  Support section.
 *
 ****************************************************************************/
static INLINE int
smb_len (const byte * packet)
{
	/* This returns the payload length stored in the NetBIOS session header. */
	return (((int)(packet[1] & 0x1)) << 16) | (((int)packet[2]) << 8) | (packet[3]);
}

static INLINE word
smb_bcc (const byte * packet)
{
	int pos = 37 + SMB_WCT (packet) * sizeof (word);

	return (word)(packet[pos] | ((word)packet[pos + 1]) << 8);
}

/* smb_valid_packet: We check if packet fulfills the basic
 * requirements of a smb packet
 */
static int
smb_valid_packet (const byte * packet)
{
	int error;

	if (memcmp(&packet[4],"\xffSMB",4) != SAME)
		error = error_smb_message_signature_missing;
	else if (smb_len(packet) < (int)(32 + 1 + SMB_WCT (packet) * sizeof(word) + sizeof(word) + SMB_BCC (packet)) )
		error = error_smb_message_too_short;
	else
		error = 0;

	return error;
}

/* smb_verify: We check if we got the answer we expected, and if we
 * got enough data. If bcc == -1, we don't care.
 */
static int
smb_verify (const byte * packet, int command, int wct, int bcc)
{
	int error;

	if (SMB_CMD (packet) != command)
		error = error_smb_message_invalid_command;
	else if (SMB_WCT (packet) < wct)
		error = error_smb_message_invalid_word_count;
	else if (bcc != -1 && SMB_BCC (packet) < bcc)
		error = error_smb_message_invalid_byte_count;
	else
		error = 0;

	return(error);
}

void
smb_translate_error_class_and_code(int errcls,int error,char ** class_ptr,char ** code_ptr)
{
	const err_class_struct * err_class = NULL;
	const err_code_struct * err_code = NULL;
	int i;

	for (i = 0; err_classes[i].class; i++)
	{
		if (err_classes[i].code == errcls)
		{
			err_class = &err_classes[i];

			if(err_class->err_msgs != NULL)
			{
				const err_code_struct * err = err_class->err_msgs;
				int j;

				for (j = 0; err[j].name; j++)
				{
					if(err[j].code == error)
					{
						err_code = &err[j];
						break;
					}
				}
			}

			break;
		}
	}

	if(err_class != NULL && err_code != NULL)
	{
		(*class_ptr)	= (char *)err_class->class;
		(*code_ptr)		= (char *)err_code->message;
	}
	else
	{
		(*class_ptr)	= "?";
		(*code_ptr)		= "?";
	}
}

int
smb_errno (int errcls, int error)
{
	int result,i;

	if (errcls == ERRDOS)
	{
		static const int map[][2] =
		{
			{ ERRbadfunc,		EINVAL },
			{ ERRbadfile,		ENOENT },
			{ ERRbadpath,		ENOENT },
			{ ERRnofids,		EMFILE },
			{ ERRnoaccess,		EPERM },
			{ ERRbadfid,		EBADF },
			{ ERRbadmcb,		EIO },
			{ ERRnomem,			ENOMEM },
			{ ERRbadmem,		EFAULT },
			{ ERRbadenv,		EIO },
			{ ERRbadformat,		EIO },
			{ ERRbadaccess,		EACCES },
			{ ERRbaddata,		E2BIG },
			{ ERRbaddrive,		ENXIO },
			{ ERRremcd,			EIO },
			{ ERRdiffdevice,	EXDEV },
			{ ERRbadshare,		ETXTBSY },
			{ ERRlock,			EDEADLK },
			{ ERRfilexists,		EEXIST },
			{ ERRinvalidparam,	EINVAL },
			{ 145,				ENOTEMPTY},	/* Directory is not empty; this is what Samba reports (2016-04-23) */
			{ 183,				EEXIST },	/* This next error seems to occur on an mv when the destination exists ("object name collision") */
			{ -1,				-1 }
		};

		result = EIO;

		for(i = 0 ; map[i][0] != -1 ; i++)
		{
			if(map[i][0] == error)
			{
				result = map[i][1];
				break;
			}
		}
	}
	else if (errcls == ERRSRV)
	{
		static const int map[][2] =
		{
			{ ERRerror,		ENFILE },
			{ ERRbadpw,		EINVAL },
			{ ERRbadtype,	EIO },
			{ ERRaccess,	EACCES },
			{ -1, -1 }
		};

		result = EIO;

		for(i = 0 ; map[i][0] != -1 ; i++)
		{
			if(map[i][0] == error)
			{
				result = map[i][1];
				break;
			}
		}
	}
	else if (errcls == ERRHRD)
	{
		static const int map[][2] =
		{
			{ ERRnowrite,	EROFS },
			{ ERRbadunit,	ENODEV },
			{ ERRnotready,	EBUSY },
			{ ERRbadcmd,	EIO },
			{ ERRdata,		EIO },
			{ ERRbadreq,	ERANGE },
			{ ERRbadshare,	ETXTBSY },
			{ ERRlock,		EDEADLK },
			{ ERRdiskfull,	ENOSPC },
			{ -1,			-1 }
		};

		result = EIO;

		for(i = 0 ; map[i][0] != -1 ; i++)
		{
			if(map[i][0] == error)
			{
				result = map[i][1];
				break;
			}
		}
	}
	else if (errcls == ERRCMD)
	{
		result = EIO;
	}
	else
	{
		result = 0;
	}

	#if DEBUG
	{
		const err_class_struct * err_class = NULL;
		const err_code_struct * err_code = NULL;
		int i;

		for (i = 0; err_classes[i].class; i++)
		{
			if (err_classes[i].code == errcls)
			{
				err_class = &err_classes[i];

				if(err_class->err_msgs != NULL)
				{
					const err_code_struct * err = err_class->err_msgs;
					int j;

					for (j = 0; err[j].name; j++)
					{
						if(err[j].code == error)
						{
							err_code = &err[j];
							break;
						}
					}
				}

				break;
			}
		}

		if(err_class != NULL && err_code != NULL)
		{
			D(("translated error code %ld/%ld (%s/%s) to %ld (%s)",
				errcls,error,err_class->class,err_code->message,result,strerror(result)));
		}
		else
		{
			D(("no proper translation for error code %ld/%ld to %ld (%s)",
				errcls,error,result,strerror(result)));
		}
	}
	#endif /* DEBUG */

	return(result);
}

#if DEBUG

static char
print_char (char c)
{
	if ((c < ' ') || (c > '~'))
		return '.';

	return c;
}

static void
smb_dump_packet (const byte * packet)
{
	int i, j, len;
	int errcls, error;

	errcls = (int) packet[9];
	error = (int) (int) (packet[11] | ((int)packet[12]) << 8);

	D(("smb_len = %ld valid = %ld", smb_len (packet), smb_valid_packet (packet)));
	D(("smb_cmd = %ld smb_wct = %ld smb_bcc = %ld", packet[8], SMB_WCT (packet), SMB_BCC (packet)));
	D(("smb_rcls = %ld smb_err = %ld", errcls, error));

	if (errcls)
		smb_printerr (errcls, error);

	len = smb_len (packet);
	if (len > 100)
		len = 100;

	PRINTHEADER();

	for (i = 0; i < len; i += 10)
	{
		PRINTF (("%03ld:", i));

		for (j = i; j < i + 10; j++)
		{
			if (j < len)
				PRINTF (("%02lx ", packet[j]));
			else
				PRINTF (("   "));
		}

		PRINTF ((": "));

		for (j = i; j < i + 10; j++)
		{
			if (j < len)
				PRINTF (("%lc", print_char (packet[j])));
		}

		PRINTF (("\n"));
	}
}

#endif /* DEBUG */

/* smb_request_ok: We do the request and check the answer
 * completely. Returns 0 for success and -1 for failure.
 */
static int
smb_request_ok_with_payload (
	struct smb_server *	server,
	int					command,
	int					wct,
	int					bcc,
	void *				input_payload,
	const void *		output_payload,
	int					payload_size,
	int *				error_ptr)
{
	int result;
	int error;

	server->rcls = 0;
	server->err = 0;

	/* Send the message and wait for the response to arrive. */
	result = smb_request (server, command, input_payload, output_payload, payload_size, error_ptr);

	/* smb_request() failed? */
	if (result < 0)
	{
		SHOWMSG("smb_request failed");
	}
	/* The message received is inconsistent? */
	else if ((error = smb_valid_packet (server->transmit_buffer)) != 0)
	{
		SHOWMSG("not a valid packet!");

		(*error_ptr) = error;
		result = -1;
	}
	/* An error condition was flagged? */
	else if (server->rcls != 0)
	{
		smb_printerr (server->rcls, server->err);

		(*error_ptr) = error_check_smb_error;
		result = -1;
	}
	/* The message received does not contain the expected
	 * number of parameters and/or payload? A bcc value of
	 * -1 means that payload size should be ignored.
	 */
	else if ((error = smb_verify (server->transmit_buffer, command, wct, bcc)) != 0)
	{
		SHOWMSG("smb_verify failed");

		(*error_ptr) = error;
		result = -1;
	}
	else
	{
		D(("smb_request() returned %ld bytes", result));

		/* Return 0 for success, rather than the number of
		 * bytes received.
		 */
		result = 0;
	}

	if(result < 0)
		smb_check_server_connection(server, (*error_ptr));

	return(result);
}

/* Same thing as smb_request_ok(), but without this payload
 * business...
 */
static int
smb_request_ok (struct smb_server *s, int command, int wct, int bcc, int * error_ptr)
{
	return(smb_request_ok_with_payload (s, command, wct, bcc, NULL, NULL, 0, error_ptr));
}

/* Try to reopen a file after the server has dropped the connection, or
 * was disconnected.
 */
static int
reopen_entry(struct smb_server *server, struct smb_dirent *entry,int * error_ptr)
{
	int result;

	ASSERT( server != NULL && entry != NULL );

	if(!entry->opened)
	{
		int ignored_error;

		D(("trying to reopen file '%s'", escape_name(entry->complete_path)));

		result = smb_proc_open (server, entry->complete_path, entry->len, entry->writable, FALSE, entry, error_ptr != NULL ? error_ptr : &ignored_error);
	}
	else
	{
		result = 0;
	}

	return(result);
}

/* smb_retry: This function should be called when smb_request_ok has
 * indicated an error. If the error was indicated because the
 * connection was killed, we try to reconnect. If smb_retry returns FALSE,
 * the error was indicated for another reason, so a retry would not be
 * of any use.
 */
static int
smb_retry (struct smb_server *server)
{
	int success = FALSE;
	int ignored_error;

	if (server->state == CONN_VALID)
		goto out;

	smb_release (server);

	/* Stop means stop. */
	if(server->dont_retry)
		goto out;

	if (smb_proc_reconnect (server, &ignored_error) < 0)
	{
		SHOWMSG("smb_proc_reconnect failed");

		server->state = CONN_RETRIED;
		goto out;
	}

	server->state = CONN_VALID;
	success = TRUE;

 out:

	return success;
}

/* smb_setup_header: We completely set up the packet. You only have to
 * insert the command-specific fields.
 *
 * Returns a pointer to the SMB_Data part of the packet, which
 * is exactly bcc bytes in size.
 */
static byte *
smb_setup_header (struct smb_server *server, byte command, int wct, int bcc)
{
	/* The SMB frame size comes together as follows:
	 *
	 * 32 bytes for the SMB header
	 *  1 byte for the parameter count
	 *  x words (2 bytes each) for the parameters
	 *  1 word (2 bytes) for the number of bytes to transmit (payload)
	 *  x bytes to transmit (payload)
	 */
	const int smb_frame_size = 32 + 1 + wct * sizeof (word) + sizeof (word) + bcc;
	byte *p = server->transmit_buffer;
	byte *buf = server->transmit_buffer;

	ASSERT( wct >= 0 );
	ASSERT( bcc >= 0 );

	ASSERT( smb_frame_size <= (int)server->transmit_buffer_allocation_size );

	if(smb_frame_size > (int)server->transmit_buffer_allocation_size)
		D(("Danger: total packet size (%ld) > transmit buffer allocation (%ld)!", smb_frame_size, server->transmit_buffer_allocation_size));

	/* This sets up the NetBIOS session header. 'smb_frame_size'
	 * is the amount of data that follows the header, in this case
	 * the complete size of the SMB frame, including its payload.
	 *
	 * The NetBIOS session header takes up 4 bytes of room.
	 */
	p = smb_encode_smb_length (p, smb_frame_size);

	BSET (p, 0, 0xff);
	BSET (p, 1, 'S');
	BSET (p, 2, 'M');
	BSET (p, 3, 'B');
	BSET (p, 4, command);

	/* Fixed header length (32 bytes). */
	memset (&p[5], 0, 32 - 5);

	p += 32;

	WSET (buf, smb_tid, server->tid);
	WSET (buf, smb_pid, 0); /* server->pid */
	WSET (buf, smb_uid, server->server_uid);
	WSET (buf, smb_mid, 0); /* server->mid */

	if (server->protocol > PROTOCOL_CORE)
	{
		BSET (buf, smb_flg, server->case_sensitive ? 0 : SMB_FLG_CASELESS_PATHNAMES);
		WSET (buf, smb_flg2, SMB_FLG2_KNOWS_LONG_NAMES|SMB_FLG2_EAS|(server->unicode_enabled ? SMB_FLG2_UNICODE_STRINGS : 0));
	}

	(*p++) = wct;
	p += wct * sizeof(word);

	WSET (p, 0, bcc);

	D(("total packet size=%ld, max receive size=%ld, packet buffer size=%ld",
		p + sizeof(word) + bcc - server->transmit_buffer,
		server->max_recv,
		server->transmit_buffer_allocation_size
	));

	return p + sizeof(word);
}

/* Returns how much room is still left in the transmission
 * buffer, just judging by the number of parameters and
 * the payload size.
 */
int
smb_payload_size(const struct smb_server *server, int wct, int bcc)
{
	return(server->transmit_buffer_size - (int)(32 + 1 + wct * sizeof(word) + sizeof(word) + bcc));
}

/*****************************************************************************
 *
 *  File operation section.
 *
 ****************************************************************************/

int
smb_proc_open (
	struct smb_server *server,
	const char *pathname,
	int len,
	int writable,
	int truncate_file,
	struct smb_dirent *entry,
	int * error_ptr)
{
	int result = 0;
	char *p;
	char *buf = server->transmit_buffer;
	int retry_read_only;

	ENTER();

	D(("pathname = '%s'", escape_name(pathname)));

	/* Because the original code opened every file/directory in
	 * read/write mode, we emulate the same behaviour. Why this
	 * is done is hard to tell. Presumably, some directories need
	 * to be writable for modifications to take place within.
	 *
	 * If read access is requested, we start with write access
	 * and disable truncation just to be safe. If that attempt
	 * fails due to access rights issues, we try again with read
	 * access.
	 */
	if(writable)
	{
		retry_read_only = FALSE;
	}
	else
	{
		writable = TRUE;

		retry_read_only = TRUE;

		truncate_file = FALSE;
	}

	if (!server->prefer_core_protocol && server->protocol >= PROTOCOL_NT1)
	{
		dword desired_access;
		dword share_access;
		dword create_disposition;
		dword create_options;
		dword ext_file_attributes;
		dword end_of_file_low;
		dword end_of_file_high;
		char *params;
		char *data;
		int pathname_size;
		int pathname_pad;

		SHOWMSG("we'll try SMB_COM_NT_CREATE_ANDX");

		if(server->unicode_enabled)
		{
			// Tygre 2015/05/29: Size in UTF16
			// The size is that of the bytes stored,
			// plus the Latin1 path as prefix, not
			// two bytes per char anymore in UTF16.
			pathname_size = size_utf16le_of_latin1(server, pathname);
			if(-1 == pathname_size)
			{
				// Default size
				pathname_size = 2 * (len + 1);
			}
			pathname_pad = 1;
		}
		else
		{
			pathname_size = len + 1;
			pathname_pad = 0;
		}

		ASSERT( smb_payload_size(server, 24, pathname_size + pathname_pad) >= 0 );

		while(TRUE)
		{
			if(writable)
			{
				SHOWMSG("write access required");

				/* The following does not work consistently with multiple
				 * SMB servers. Which is why we stick with generic read/write.
				 */
				/* desired_access = FILE_READ_DATA|FILE_WRITE_DATA|FILE_DELETE|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES; */

				desired_access = GENERIC_READ|GENERIC_WRITE;
			}
			else
			{
				SHOWMSG("read access is sufficient");

				/* The following does not work consistently with multiple
				 * SMB servers. Which is why we stick with generic read.
				 */
				/* desired_access = FILE_READ_DATA|FILE_READ_ATTRIBUTES; */

				desired_access = GENERIC_READ;
			}

			/* Allows others to read, write and delete the file just created.
			 * This may be useful if smbfs hangs or you need to restart your
			 * System and you need to clean up after the file you just
			 * created.
			 */
			share_access = FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE;

			if(writable && truncate_file)
			{
				create_disposition	= FILE_OVERWRITE_IF;
				create_options		= FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS;
			}
			else
			{
				create_disposition	= FILE_OPEN;
				create_options		= 0;
			}

			data = smb_setup_header (server, SMBntcreateX, 24, pathname_pad + pathname_size);

			params = SMB_VWV (server->transmit_buffer);

			params = smb_encode_byte(params, 0xFF); 						/* AndXCommand: no next command */
			params = smb_encode_byte(params, 0);							/* AndXReserved */
			params = smb_encode_word(params, 0);							/* AndXOffset */
			params = smb_encode_byte(params, 0);							/* Reserved */
			params = smb_encode_word(params, pathname_pad + pathname_size);	/* NameLength */
			params = smb_encode_dword(params, 0);							/* Flags */
			params = smb_encode_dword(params, 0);							/* RootDirectoryFID: 0 -> file name is relative to root directory */
			params = smb_encode_dword(params, desired_access);				/* DesiredAccess */
			params = smb_encode_dword(params, 0);							/* AllocationSize (low) */
			params = smb_encode_dword(params, 0);							/* AllocationSize (high) */
			params = smb_encode_dword(params, ATTR_NORMAL);					/* ExtFileAttributes */
			params = smb_encode_dword(params, share_access);				/* ShareAccess */
			params = smb_encode_dword(params, create_disposition);			/* CreateDisposition */
			params = smb_encode_dword(params, create_options);				/* CreateOptions */
			params = smb_encode_dword(params, SEC_ANONYMOUS);				/* ImpersonationLevel */
			(void) smb_encode_byte(params, 0);								/* SecurityFlags */

			/* Now for the data portion of the message */
			if(server->unicode_enabled)
			{
				/* Add a padding byte so that the following Unicode string
				 * will be word-aligned.
				 */
				(*data++) = 0;
				(void) copy_latin1_to_utf16le(server, data, pathname_size, pathname, len);
			}
			else
			{
				(void) smb_copy_data(data, pathname, pathname_size); /* Length includes the terminating NUL byte. */
			}

			SHOWMSG("requesting SMBntcreateX");

			result = smb_request_ok(server, SMBntcreateX, 34, 0, error_ptr);
			if (result < 0)
			{
				int access_error;

				SHOWMSG("that didn't work; retrying");

				/* Try again in read-only mode? */
				access_error = (*error_ptr);
				if(access_error == error_check_smb_error)
					access_error = smb_errno(server->rcls,server->err);

				if (access_error == EACCES || access_error == EPERM)
				{
					if(retry_read_only)
					{
						SHOWMSG("retrying with read-only access");

						retry_read_only = FALSE;

						writable = FALSE;

						continue;
					}
					else
					{
						goto out;
					}
				}

				if ((*error_ptr) != error_check_smb_error && smb_retry (server))
					continue;
				else
					goto out;
			}

			break;
		}

		params = SMB_VWV (server->transmit_buffer);
		params += 5; /* AndXCommand+AndXReserved+AndXOffset+OpLockLevel */

		params = smb_decode_word(params, &entry->fileid);

		params += sizeof(dword); /* CreateDisposition */

		entry->ctime = convert_long_date_to_time_t(params);
		params += 2 * sizeof(dword); /* CreateTime */

		entry->atime = convert_long_date_to_time_t(params);
		params += 2 * sizeof(dword); /* LastAccessTime */

		entry->wtime = convert_long_date_to_time_t(params);
		params += 2 * sizeof(dword); /* LastWriteTime */

		entry->mtime = convert_long_date_to_time_t(params);
		params += 2 * sizeof(dword); /* LastChangeTime */

		params = smb_decode_dword(params, &ext_file_attributes);
		entry->attr = ext_file_attributes;

		params += 2 * sizeof(dword); /* AllocationSize */

		params = smb_decode_dword(params, &end_of_file_low);
		(void) smb_decode_dword(params, &end_of_file_high);

		entry->size_low = end_of_file_low;
		entry->size_high = end_of_file_high;
	}
	else
	{
		word access_and_share_modes;
		int path_size;

		if(server->unicode_enabled)
		{
			// Tygre 2015/05/29: Size in UTF16
			// The size is that of the bytes stored,
			// plus the Latin1 path as prefix, not
			// two bytes per char anymore in UTF16.
			path_size = size_utf16le_of_latin1(server, pathname);
			if(-1 == path_size)
			{
				// Default size
				path_size = 2 * (len + 1);
			}
		}
		else
		{
			path_size = len + 1;
		}

		ASSERT( smb_payload_size(server, 2, 1 + path_size) >= 0 );

		SHOWMSG("using the old SMB_COM_OPEN");

		while(TRUE)
		{
			if(writable)
				access_and_share_modes = SMB_OPEN_SHARE_DENY_NOTHING|SMB_OPEN_ACCESS_READ_WRITE;
			else
				access_and_share_modes = SMB_OPEN_SHARE_DENY_NOTHING|SMB_OPEN_ACCESS_READ_ONLY;

			p = smb_setup_header (server, SMBopen, 2, 1 + path_size);
			WSET (buf, smb_vwv0, access_and_share_modes);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_HIDDEN|SMB_FILE_ATTRIBUTE_SYSTEM|SMB_FILE_ATTRIBUTE_DIRECTORY);

			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A NUL-terminated string follows. */
				copy_latin1_to_utf16le(server, p, path_size, pathname, len);
			}
			else
			{
				smb_encode_ascii (p, pathname, len);
			}

			result = smb_request_ok (server, SMBopen, 7, 0, error_ptr);
			if (result < 0)
			{
				int access_error;

				SHOWMSG("that didn't work; retrying");

				/* Try again in read-only mode? */
				access_error = (*error_ptr);
				if(access_error == error_check_smb_error)
					access_error = smb_errno(server->rcls,server->err);

				if (access_error == EACCES || access_error == EPERM)
				{
					if(retry_read_only)
					{
						SHOWMSG("retrying with read-only access");

						retry_read_only = FALSE;

						writable = FALSE;

						continue;
					}

					goto out;
				}

				if ((*error_ptr) != error_check_smb_error && smb_retry (server))
					continue;
				else
					goto out;
			}

			break;
		}

		/* We should now have data in vwv[0..6]. */
		entry->fileid = WVAL (buf, smb_vwv0);

		entry->attr = WVAL (buf, smb_vwv1);

		/* This is actually just the wtime value, but we use it
		 * in all other places as well.
		 */
		entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc(DVAL (buf, smb_vwv2)); /* Note: this is UTIME, and should be the server's local time. */

		#if DEBUG
		{
			struct tm tm_utc;
			struct tm tm_local;

			seconds_to_tm(entry->mtime,&tm_utc);

			D(("modification time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
				tm_utc.tm_year + 1900,
				tm_utc.tm_mon+1,
				tm_utc.tm_mday,
				tm_utc.tm_hour,
				tm_utc.tm_min,
				tm_utc.tm_sec));

			seconds_to_tm(DVAL (buf, smb_vwv2),&tm_local);

			D(("                    %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
				tm_local.tm_year + 1900,
				tm_local.tm_mon+1,
				tm_local.tm_mday,
				tm_local.tm_hour,
				tm_local.tm_min,
				tm_local.tm_sec));
		}
		#endif /* DEBUG */

		entry->size_low = DVAL (buf, smb_vwv4);
		entry->size_high = 0;
	}

	entry->opened = TRUE;
	entry->writable = writable;

 out:

	RETURN(result);
	return(result);
}

/* smb_proc_close: in finfo->mtime we can send a modification time to
 * the server
 */
int
smb_proc_close (struct smb_server *server, word fileid, dword wtime, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	/* Note: wtime is UTIME, and should be the server's local time. */
	if(wtime != 0 && wtime != (dword)-1)
		wtime = utc2local(wtime);

	smb_setup_header (server, SMBclose, 3, 0);
	WSET (buf, smb_vwv0, fileid);
	DSET (buf, smb_vwv1, wtime);

	result = smb_request_ok (server, SMBclose, 0, 0, error_ptr);

	return result;
}

/* In smb_proc_read and smb_proc_write we retry, but we update
 * the file-id to be valid again after a reconnection.
 */
int
smb_proc_read (
	struct smb_server *server,
	struct smb_dirent *finfo,
	off_t offset,
	long count,
	char *data,
	int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	ASSERT( count <= 65535 );

 retry:

	smb_setup_header (server, SMBread, 5, 0);

	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, count);
	DSET (buf, smb_vwv2, offset);
	WSET (buf, smb_vwv4, 0);

	D(("requesting %ld bytes", count));

	result = smb_request_ok_with_payload (server, SMBread, 5, -1, data, NULL, count, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
		goto out;
	}

	/* The buffer format must be 1; smb_request_ok_with_payload() already checked this. */
	D(("buffer_format=%ld, should be %ld", BVAL(buf, NETBIOS_HEADER_SIZE+45), 1));

	result = WVAL (buf, NETBIOS_HEADER_SIZE+46); /* count of bytes to read */

	ASSERT( result <= count );

	D(("read %ld bytes (should be < %ld)", result, count));

 out:

	return result;
}

/* count must be <= 65535. No error number is returned. A result of 0
 * indicates an error, which has to be investigated by a normal read
 * call.
 */
int
smb_proc_read_raw (
	struct smb_server *server,
	struct smb_dirent *finfo,
	const QUAD * const offset_quad,
	long count,
	char * data,
	int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	ASSERT( count <= 65535 );

 retry:

	smb_setup_header (server, SMBreadbraw, 10, 0);

	WSET (buf, smb_vwv0, finfo->fileid);
	DSET (buf, smb_vwv1, offset_quad->Low);
	WSET (buf, smb_vwv3, count); /* maxcnt */
	WSET (buf, smb_vwv4, 0); /* mincnt */
	DSET (buf, smb_vwv5, 0); /* timeout */
	WSET (buf, smb_vwv7, 0); /* reserved */
	DSET (buf, smb_vwv8, offset_quad->High);

	result = smb_request_read_raw (server, data, count, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
	}

	return result;
}

int
smb_proc_write (
	struct smb_server *server,
	struct smb_dirent *finfo,
	off_t offset,
	long count,
	const char *data,
	int * error_ptr)
{
	int result;
	char *buf = server->transmit_buffer;
	byte *p;

	ASSERT( count <= 65535 );

 retry:

	p = smb_setup_header (server, SMBwrite, 5, count + 3);
	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, count);
	DSET (buf, smb_vwv2, offset);
	WSET (buf, smb_vwv4, 0);

	(*p++) = 1; /* Buffer format - this field must be 1 */
	WSET (p, 0, count); /* Data length - this field must match what the count field in the SMB header says */

	result = smb_request_ok_with_payload (server, SMBwrite, 1, 0, NULL, data, count, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
	}
	else
	{
		result = WVAL (buf, smb_vwv0);
	}

	return result;
}

int
smb_proc_write_raw (
	struct smb_server *server,
	struct smb_dirent *finfo,
	const QUAD * const offset_quad,
	long count,
	const char *data,
	int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int num_bytes_written = 0;
	int result;
	long max_len;
	long len;
	byte *p;

	ASSERT( count <= 65535 );

	D(("number of bytes to send = %ld", count));

	/* Calculate the maximum number of bytes that could be transferred with
	 * a single SMB_COM_WRITE_RAW packet...
	 *
	 * 'max_buffer_size' is the maximum size of a complete SMB message
	 * including the message header, the parameter and data blocks.
	 *
	 * The message header accounts for
	 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
	 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
	 * = 32 bytes
	 *
	 * The parameters of a SMB_COM_WRITE_RAW command account for
	 * 1(wordcount)+2(fid)+2(countofbytes)+2(reserved1)+4(offset)+
	 * 4(timeout)+2(writemode)+4(reserved2)+2(datalength)+2(dataoffset)+
	 * 4(offset high)
	 * = 29 bytes
	 *
	 * The data part of a SMB_COM_WRITE_RAW command account for
	 * 2(bytecount)+0(pad) = 2 bytes, not including
	 * the actual payload
	 *
	 * This leaves 'max_buffer_size' - 63 for the payload.
	 */
	max_len = server->max_buffer_size;
	if(max_len > 65535)
		max_len = 65535;

	max_len -= 63;

	D(("maximum length for payload = %ld bytes", max_len));

	/* Number of bytes to write is smaller than the maximum
	 * number of bytes which may be sent in a single SMB
	 * message, including parameter and data fields?
	 */
	if (count <= max_len)
	{
		D(("count (%ld) <= max_len (%ld) -- send no data with the message.",count,max_len));

		len = 0; /* Send a zero length SMB_COM_WRITE_RAW message, followed by the raw data. */
	}
	else
	{
		len = count - max_len; /* Send some of the data as part of the SMB_COM_WRITE_RAW message, followed by the remaining raw data. */

		D(("count (%ld) > max_len (%ld) -- send %ld bytes with the message.",count,max_len,len));
	}

 retry:

	p = smb_setup_header (server, SMBwritebraw, 14, len);

	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, count);
	WSET (buf, smb_vwv2, 0); /* reserved */
	DSET (buf, smb_vwv3, offset_quad->Low);
	DSET (buf, smb_vwv5, 0); /* timeout */

	if(server->write_behind)
		WSET (buf, smb_vwv7, 0); /* do not send a final result response. */
	else
		WSET (buf, smb_vwv7, 1); /* send final result response */

	DSET (buf, smb_vwv8, 0); /* reserved */

	WSET (buf, smb_vwv10, len);
	WSET (buf, smb_vwv11, p - smb_base(buf));
	DSET (buf, smb_vwv12, offset_quad->High);

	SHOWMSG("requesting SMBwritebraw");

	result = smb_request_ok_with_payload (server, SMBwritebraw, 1, 0, NULL, data, len, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
		goto out;
	}

	num_bytes_written += len;

	data += len;
	count -= len;

	D(("bytes sent so far = %ld", num_bytes_written));

	if(count > 0)
	{
		D(("sending %ld bytes of data (raw)",count));

		ASSERT( count <= 65535 );

		result = smb_request_write_raw (server, data, count, error_ptr);
		if (result < 0)
		{
			/* Roll back the counters */
			num_bytes_written -= len;

			data -= len;
			count += len;

			if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			{
				if(reopen_entry(server,finfo,NULL) == 0)
					goto retry;
			}

			SHOWMSG("that didn't work.");
			goto out;
		}

		if(server->write_behind)
		{
			/* We just assume success; the next file operation to follow
			 * will set an error status if something went wrong.
			 */
			num_bytes_written += count;
		}
		else
		{
			int error;

			/* We have to do the checks of smb_request_ok here as well */
			if ((error = smb_valid_packet (server->transmit_buffer)) != 0)
			{
				SHOWMSG("not a valid packet!");

				(*error_ptr) = error;
				result = -1;

				goto out;
			}
			else if (server->rcls != 0)
			{
				D(("server error %ld/%ld", server->rcls, server->err));

				smb_printerr (server->rcls, server->err);

				(*error_ptr) = error_check_smb_error;
				result = -1;

				goto out;
			}

			num_bytes_written += count;
		}

		D(("bytes sent so far = %ld", num_bytes_written));
	}

	result = num_bytes_written;

 out:

	return result;
}

int
smb_proc_writex (
	struct smb_server *server,
	struct smb_dirent *finfo,
	const QUAD * const offset_quad,
	long count,
	const char *data,
	int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;
	byte *p;

	ASSERT( count <= 65535 );

	D(("number of bytes to send = %ld", count));

 retry:

	p = smb_setup_header (server, SMBwriteX, server->protocol >= PROTOCOL_NT1 ? 14 : 12, 2+1+count);

	BSET (buf, smb_vwv0, 0xFF);	/* AndXCommand/AndXReserved - no additional SMB commands provided */
	WSET (buf, smb_vwv1, 0); /* AndXOffset */
	WSET (buf, smb_vwv2, finfo->fileid); /* fid */
	DSET (buf, smb_vwv3, offset_quad->Low); /* offset */
	DSET (buf, smb_vwv5, 0); /* timeout */
	WSET (buf, smb_vwv7, 0); /* write mode */
	WSET (buf, smb_vwv8, 0); /* remaining */
	WSET (buf, smb_vwv9, 0); /* reserved */
	WSET (buf, smb_vwv10, count); /* data length */

	if(server->protocol >= PROTOCOL_NT1)
	{
		WSET (buf, smb_vwv11, 64+2); /* data offset */
		DSET (buf, smb_vwv12, offset_quad->High); /* high offset */
	}
	else
	{
		WSET (buf, smb_vwv11, 60+2); /* data offset */
	}

	/* Now for the data portion of the message */

	WSET (p, 0, 1+count); p += 2; /* Byte count (1 pad byte + data bytes)  */
	(*p) = 0; /* Padding byte that must be ignored */

	D(("requesting SMBwriteX: offset=%s, count=%ld", convert_quad_to_string(offset_quad), count));

	result = smb_request_ok_with_payload (server, SMBwriteX, 6, 0, NULL, data, count, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
	}
	else
	{
		word available;

		p = SMB_VWV (server->transmit_buffer);
		smb_decode_word (p + 4, &available);

		D(("number of bytes written = %ld", available));

		result = available;
	}

	return result;
}

int
smb_proc_readx (
	struct smb_server *server,
	struct smb_dirent *finfo,
	const QUAD * const offset_quad,
	long count,
	char *data,
	int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;
	byte *p;

	ASSERT( count <= 65535 );

	D(("number of bytes to read = %ld", count));

 retry:

	p = smb_setup_header (server, SMBreadX, server->protocol >= PROTOCOL_NT1 ? 12 : 10, 2);

	BSET (buf, smb_vwv0, 0xFF);	/* AndXCommand/AndXReserved - no additional SMB commands provided */
	WSET (buf, smb_vwv1, 0); /* AndXOffset */
	WSET (buf, smb_vwv2, finfo->fileid); /* fid */
	DSET (buf, smb_vwv3, offset_quad->Low); /* offset */
	WSET (buf, smb_vwv5, count); /* MaxCountOfBytesToReturn */
	WSET (buf, smb_vwv6, 0); /* MinCountOfBytesToReturn */
	DSET (buf, smb_vwv7, 0); /* timeout */
	WSET (buf, smb_vwv9, 0); /* remaining */

	if(server->protocol >= PROTOCOL_NT1)
		DSET (buf, smb_vwv10, offset_quad->High); /* OffsetHigh */

	/* Now for the data portion of the message */

	WSET (p, 0, 0); /* Byte count */

	D(("requesting SMBreadX: offset=%s, count=%ld", convert_quad_to_string(offset_quad), count));

	result = smb_request_ok_with_payload (server, SMBreadX, 7, 0, data, NULL, count, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
	}
	else
	{
		word data_length;

		p = SMB_VWV (server->transmit_buffer);
		smb_decode_word (p + 10, &data_length);

		D(("number of bytes read = %ld", data_length));

		result = data_length;
	}

	return result;
}

/* smb_proc_lockingX: We don't chain any further packets to the initial one */
int
smb_proc_lockingX (
	struct smb_server *server,
	struct smb_dirent *finfo,
	const struct smb_lkrng *locks,
	int num_entries,
	int mode,
	long timeout,
	int * error_ptr)
{
	int result;
	int num_locks, num_unlocks;
	char *buf = server->transmit_buffer;
	char *data;
	const struct smb_lkrng *p;
	int i;

	num_locks = num_unlocks = 0;

	if (mode & 2)
		num_unlocks = num_entries;
	else
		num_locks = num_entries;

	ASSERT( smb_payload_size(server, 8, num_entries * 10) >= 0 );

 retry:

	data = smb_setup_header(server, SMBlockingX, 8, num_entries * 10);

	BSET (buf, smb_vwv0, 0xFF);
	WSET (buf, smb_vwv1, 0);
	WSET (buf, smb_vwv2, finfo->fileid);
	WSET (buf, smb_vwv3, mode & 1);	/* must be WSET() or new oplock level will be random */
	DSET (buf, smb_vwv4, timeout);
	WSET (buf, smb_vwv6, num_unlocks);
	WSET (buf, smb_vwv7, num_locks);

	for (i = 0, p = locks; i < num_entries; i++, p++)
	{
		WSET (data, SMB_LPID_OFFSET(i), 0); /* server->pid */
		DSET (data, SMB_LKOFF_OFFSET(i), p->offset);
		DSET (data, SMB_LKLEN_OFFSET(i), p->len);
	}

	result = smb_request_ok (server, SMBlockingX, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
	}

	return result;
}

/* smb_proc_do_create: We expect entry->attry and entry->ctime to be set. */
int
smb_proc_create (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr)
{
	dword local_time;
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	int path_size;

	local_time = utc2local(entry->ctime); /* Note: this is UTIME, and should be the server's local time. */

	#if DEBUG
	{
		struct tm tm_local;
		struct tm tm_utc;

		seconds_to_tm(entry->ctime,&tm_utc);

		D(("creation time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
			tm_utc.tm_year + 1900,
			tm_utc.tm_mon+1,
			tm_utc.tm_mday,
			tm_utc.tm_hour,
			tm_utc.tm_min,
			tm_utc.tm_sec));

		seconds_to_tm(local_time,&tm_local);

		D(("                %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
			tm_local.tm_year + 1900,
			tm_local.tm_mon+1,
			tm_local.tm_mday,
			tm_local.tm_hour,
			tm_local.tm_min,
			tm_local.tm_sec));
	}
	#endif /* DEBUG */

	if(server->unicode_enabled)
	{
		// Tygre 2015/05/29: Size in UTF16
		// The size is that of the bytes stored,
		// plus the Latin1 path as prefix, not
		// two bytes per char anymore in UTF16.
		path_size = size_utf16le_of_latin1(server, path);
		if(-1 == path_size)
		{
			// Default size
			path_size = 2 * (len + 1);
		}
	}
	else
	{
		path_size = len + 1;
	}

 retry:

	ASSERT( smb_payload_size(server, 3, 1 + path_size) >= 0 );

	p = smb_setup_header (server, SMBcreate, 3, 1 + path_size);
	WSET (buf, smb_vwv0, entry->attr);
	DSET (buf, smb_vwv1, local_time);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		copy_latin1_to_utf16le(server, p, path_size, path, len);
	}
	else
	{
		smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBcreate, 1, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
		else
			goto out;
	}

	entry->opened = TRUE;
	entry->fileid = WVAL (buf, smb_vwv0);

 out:

	return result;
}

int
smb_proc_mv (
	struct smb_server *server,
	const char *old_path,
	const int old_path_len,
	const char *new_path,
	const int new_path_len,
	int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int size;
	int result;

	// TODO: Tygre
	if(server->unicode_enabled)
		size = 2 + 1 + 2 * (old_path_len+1) + 2 * (new_path_len+1);
	else
		size = 2 + 1 + (old_path_len+1) + 1 + (new_path_len+1);

	ASSERT( smb_payload_size(server, 1, size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBmv, 1, size);

	WSET (buf, smb_vwv0, SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_HIDDEN);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		p += copy_latin1_to_utf16le(server, p,2 * (old_path_len+1),old_path,old_path_len);

		(*p++) = 4; /* A NUL-terminated string follows. */

		(*p++) = 0; /* Padding byte, allowing for the string to be word-aligned. */
		(void) copy_latin1_to_utf16le(server, p,2 * (new_path_len+1),new_path,new_path_len);
	}
	else
	{
		p = smb_encode_ascii (p, old_path, old_path_len);
		(void) smb_encode_ascii (p, new_path, new_path_len);
	}

	result = smb_request_ok (server, SMBmv, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
	}

	return result;
}

int
smb_proc_mkdir (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	int path_size;
	int result;
	char *p;

	// TODO: Tygre
	if(server->unicode_enabled)
		path_size = 2 * (len + 1);
	else
		path_size = len + 1;

 retry:

	ASSERT( smb_payload_size(server, 0, 1 + path_size) >= 0 );

	p = smb_setup_header (server, SMBmkdir, 0, 1 + path_size);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		(void) copy_latin1_to_utf16le(server, p,path_size,path,len);
	}
	else
	{
		(void) smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBmkdir, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
	}

 out:

	return result;
}

int
smb_proc_rmdir (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	int path_size;
	int result;
	char *p;

	// TODO: Tygre
	if(server->unicode_enabled)
		path_size = 2 * (len + 1);
	else
		path_size = len + 1;

	ASSERT( smb_payload_size(server, 0, 1 + path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBrmdir, 0, 1 + path_size);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		(void) copy_latin1_to_utf16le(server, p,path_size,path,len);
	}
	else
	{
		(void) smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBrmdir, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
	}

	return result;
}

int
smb_proc_unlink (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	int path_size;
	char *p;
	char *buf = server->transmit_buffer;
	int result;

	// TODO: Tygre
	if(server->unicode_enabled)
		path_size = 2 * (len + 1);
	else
		path_size = len + 1;

	ASSERT( smb_payload_size(server, 1, 1 + path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBunlink, 1, 1 + path_size);

	/* Allow for system and hidden files to be deleted, too. After
	 * all, we show these in the directory lists.
	 */
	WSET (buf, smb_vwv0, SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_HIDDEN);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		(void) copy_latin1_to_utf16le(server, p,path_size,path,len);
	}
	else
	{
		(void) smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBunlink, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
	}

	return result;
}

/* This does not really truncate the file, making it shorter. It just
 * writes "enough" data to the file to make it as large as requested.
 */
int
smb_proc_trunc (struct smb_server *server, struct smb_dirent *entry, dword length, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int result;

	ASSERT( smb_payload_size(server, 5, 3) >= 0 );

 retry:

	p = smb_setup_header (server, SMBwrite, 5, 3);
	WSET (buf, smb_vwv0, entry->fileid);
	WSET (buf, smb_vwv1, 0);
	DSET (buf, smb_vwv2, length);
	WSET (buf, smb_vwv4, 0);

	smb_encode_ascii (p, "", 0);

	result = smb_request_ok (server, SMBwrite, 1, 0, error_ptr);
	if(result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,entry,NULL) == 0)
				goto retry;
		}
	}
	else
	{
		result = DVAL(buf, smb_vwv0);
	}

	return result;
}

static void
smb_decode_short_dirent (dircache_t * dircache, const char *p, struct smb_dirent *entry)
{
	int name_len;
	int i;

	ASSERT( sizeof(dircache->search_resume_key) >= SMB_RESUME_KEY_SIZE );
	memcpy(dircache->search_resume_key, p, SMB_RESUME_KEY_SIZE);
	p += SMB_RESUME_KEY_SIZE;

	entry->attr = BVAL (p, 0);
	entry->mtime = entry->atime = entry->ctime = entry->wtime = date_dos2unix (WVAL (p, 1), WVAL (p, 3));
	entry->size_low = DVAL (p, 5);
	entry->size_high = 0;

	/* The name is given in 8.3 MS-DOS style format, including the "."
	 * delimiter. This is a NUL-terminated OEM string, with one byte per
	 * character. If the name is shorter than 12 characters, it is
	 * padded with " " (space) characters.
	 */
	name_len = 12;

	p += 9;

	/* How long is the NUL-terminated string really? */
	for(i = 0 ; i < name_len ; i++)
	{
		if(p[i] == '\0')
		{
			name_len = i;
			break;
		}
	}

	/* Remove padding characters from the name. */
	while(name_len > 0 && p[name_len-1] == ' ')
		name_len--;

	ASSERT( name_len < entry->complete_path_size );

	memcpy (entry->complete_path, p, name_len);

	entry->complete_path[name_len] = '\0';

	D(("name = '%s'", escape_name(entry->complete_path)));

	#if DEBUG
	{
		struct tm tm;

		seconds_to_tm(entry->mtime,&tm);

		D(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",
			tm.tm_year + 1900,
			tm.tm_mon+1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec));
	}
	#endif /* DEBUG */
}

/* This routine is used to read in directory entries from the network.
 * Note that it is for short directory name seeks, i.e.: protocol < PROTOCOL_LANMAN2
 */
static int
smb_proc_readdir_short (
	struct smb_server *server,
	const char *path,
	dircache_t * dircache,
	int * end_of_search_ptr,
	int * error_ptr)
{
	char *p;
	char *buf;
	int result = -1;
	int i;
	int is_first, total_count;
	struct smb_dirent * entry;
	word bcc;
	word count;
	word datalength;
	char resume_key[SMB_RESUME_KEY_SIZE];

	int entries_asked;
	int path_len = strlen (path);
	int mask_len;
	int mask_size;
	char * mask;
	int end_of_search = 0;

	mask = malloc(path_len + 4 + 1);
	if (mask == NULL)
	{
		(*error_ptr) = ENOMEM;
		goto out;
	}

	memcpy(mask, path, path_len);
	memcpy(&mask[path_len], "\\*.*", 5); /* Length includes terminating NUL. */

	mask_len = strlen (mask);

	if(server->unicode_enabled)
	{
		// Tygre 2015/05/29: Size in UTF16
		// The size is that of the bytes stored,
		// plus the Latin1 path as prefix, not
		// two bytes per char anymore in UTF16.
		mask_size = size_utf16le_of_latin1(server, path);
		if(-1 == mask_size)
		{
			// Default size
			mask_size = 2 * (mask_len + 1);
		}
	}
	else
	{
		mask_size = mask_len+1;
	}

	SHOWMSG("SMB call readdir_short");
	D(("         mask = '%s'", escape_name(mask)));

	buf = server->transmit_buffer;

	memset(resume_key, 0, sizeof(resume_key));

 retry:

	if(dircache->sid == -1)
	{
		is_first = TRUE;

		SHOWMSG("start scanning from the top");
	}
	else
	{
		is_first = FALSE;

		memcpy(resume_key, dircache->search_resume_key, SMB_RESUME_KEY_SIZE);
	}

	total_count = 0;

	entry = get_first_dircache_entry(dircache);

	while (entry != NULL)
	{
		entries_asked = get_dircache_entries_available(dircache);

		if (is_first)
		{
			SHOWMSG("reading first directory entries");

			ASSERT( smb_payload_size(server, 2, 1 + mask_size + 3) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, 1 + mask_size + 3);
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_DIRECTORY);

			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A NUL-terminated string follows. */
				p += copy_latin1_to_utf16le(server, p, mask_size, mask, mask_len);
			}
			else
			{
				p = smb_encode_ascii (p, mask, strlen (mask));
			}

			(*p++) = 5; /* a variable block follows. */
			(void) smb_encode_word (p, 0); /* resume key length = 0, i.e. this is the initial search command. */

			is_first = FALSE;
		}
		else
		{
			int size;

			SHOWMSG("reading next directory entries");

			// TODO: Tygre
			if(server->unicode_enabled)
				size = 1 + 2 * (1) + 3 + SMB_RESUME_KEY_SIZE;
			else
				size = 1 + 1 + 3 + SMB_RESUME_KEY_SIZE;

			ASSERT( smb_payload_size(server, 2, size) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, size);
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_DIRECTORY);

			/* Add an empty file name. */
			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A NUL-terminated string follows. */
				p += copy_latin1_to_utf16le(server, p,2 * (1),"",0);
			}
			else
			{
				p = smb_encode_ascii (p, "", 0);
			}

			/* Add the resume key. */
			(void) smb_encode_vblock (p, resume_key, SMB_RESUME_KEY_SIZE);
		}

		if (smb_request_ok (server, SMBsearch, 1, -1, error_ptr) < 0)
		{
			if (server->rcls == ERRDOS && server->err == ERRnofiles)
			{
				SHOWMSG("not resuming this scan operation");

				end_of_search = TRUE;

				dircache->sid = -1;

				break;
			}

			if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			{
				SHOWMSG("retrying...");

				goto retry;
			}
			else
			{
				goto out;
			}
		}

		p = SMB_VWV (server->transmit_buffer);
		p = smb_decode_word (p, &count); /* vwv[0] = count-returned */

		p = smb_decode_word (p, &bcc);

		D(("number of directory entries returned = %ld", count));

		if (count == 0)
			break;

		ASSERT( count <= entries_asked );

		ASSERT (bcc == count * SMB_DIRINFO_SIZE + 3);

		if (bcc != count * SMB_DIRINFO_SIZE + 3)
		{
			D(("byte count (%ld) does not match expected size (%ld)", bcc, count * SMB_DIRINFO_SIZE + 3));

			(*error_ptr) = error_invalid_directory_size;

			goto out;
		}

		if((*p++) != 5)
		{
			D(("buffer format mismatch (should be 5, is %ld)", p[-1]));

			(*error_ptr) = error_invalid_directory_size;

			goto out;
		}

		p = smb_decode_word (p, &datalength);

		if(datalength != SMB_DIRINFO_SIZE * count)
		{
			D(("data length (%ld) does not match expected size (%ld)", datalength, count * SMB_DIRINFO_SIZE));

			(*error_ptr) = error_invalid_directory_size;

			goto out;
		}

		/* Now we are ready to parse smb directory entries. */
		for (i = 0; entry != NULL && i < count; i++)
		{
			smb_decode_short_dirent (dircache, p, entry);
			p += SMB_DIRINFO_SIZE;

			entry = get_next_dircache_entry(dircache);

			ASSERT( entry == NULL || i+1 == count );

			if(entry == NULL && i+1 < count)
				SHOWMSG("ran out of directory cache entries, which should never happen...");

			total_count++;
		}

		ASSERT( sizeof(dircache->search_resume_key) >= SMB_RESUME_KEY_SIZE );
		memcpy(resume_key, dircache->search_resume_key, SMB_RESUME_KEY_SIZE);

		dircache->sid = 0;
	}

	result = total_count;

 out:

	if(mask != NULL)
		free(mask);

	if(result == -1)
	{
		SHOWMSG("not resuming this scan operation");

		dircache->sid = -1;
	}

	(*end_of_search_ptr) = end_of_search;

	D(("number of entries read = %ld", result));

	return result;
}

/*****************************************************************************/

/* Translate an 8 byte "filetime" structure to a 'time_t'.
 * It's originally in "100ns units since jan 1st 1601".
 *
 * Unlike the Samba implementation of that date conversion
 * algorithm this one tries to perform the entire
 * calculation using integer operations only.
 */
static time_t
convert_long_date_to_time_t(const char * p)
{
	QUAD adjust;
	QUAD long_date;
	ULONG underflow;
	time_t result;

	/* Extract the 64 bit time value. */
	long_date.Low	= DVAL(p,0);
	long_date.High	= DVAL(p,4);

	/* Divide by 10,000,000 to convert the time from 100ns
	 * units into seconds.
	 */
	divide_64_by_32(&long_date,10000000,&long_date);

	/* Adjust by 369 years (11,644,473,600 seconds) to convert
	 * from the epoch beginning on January 1st 1601 to the one
	 * beginning on January 1st 1970 (the Unix epoch).
	 */
	adjust.Low	= 0xb6109100;
	adjust.High	= 0x00000002;

	underflow = subtract_64_from_64_to_64(&long_date,&adjust,&long_date);

	/* If the result did not produce an underflow or overflow,
	 * return the number of seconds encoded in the least
	 * significant word of the result.
	 */
	if(underflow == 0 && long_date.High == 0)
		result = long_date.Low;
	else
		result = 0;

	return(result);
}

/*****************************************************************************/

/* Translate a 'time_t' value into an SMB file time, which is
 * the equivalent in "100ns units since jan 1st 1601".
 */
static void
convert_time_t_to_long_date(time_t t, QUAD * long_date)
{
	QUAD adjust;

	long_date->Low	= t;
	long_date->High	= 0;

	/* Adjust by 369 years (11,644,473,600 seconds) to convert
	 * from the epoch beginning on January 1st 1601 to the one
	 * beginning on January 1st 1970 (the Unix epoch).
	 */
	adjust.Low	= 0xb6109100;
	adjust.High	= 0x00000002;

	add_64_plus_64_to_64(&adjust,long_date,long_date);

	/* Multiply by 10,000,000 to convert the time from
	 * seconds to 100ns units.
	 */
	multiply_64_by_32_to_64(long_date,10000000,long_date);
}

/*****************************************************************************/

/* interpret a long filename structure */
static int
smb_decode_long_dirent (
	const struct smb_server *server,
	const char *p,
	struct smb_dirent *finfo,
	int level,
	int * entry_length_ptr)
{
	int success = TRUE;

	ENTER();

	ASSERT( entry_length_ptr != NULL );

	switch (level)
	{
		case SMB_INFO_STANDARD:

			SHOWMSG("SMB_INFO_STANDARD");

			(*entry_length_ptr) = 28 + BVAL (p, 26);

			if (finfo != NULL)
			{
				const char * name;
				int name_size;
				int name_len;

				name = &p[27];
				name_size = BVAL (p, 26);

				SHOWVALUE(name_size);

				/* Figure out how long the string really is. It's
				 * supposed to be NUL-terminated.
				 */
				if(server->unicode_enabled)
					name_len = strnlen_utf16(name, name_size);
				else
					name_len = strnlen(name, name_size);

				SHOWVALUE(name_len);

				/* Skip directory entries whose names we cannot store. */
				if(name_len >= (int)finfo->complete_path_size)
				{
					D(("name length >= %lu (skipping it)", (unsigned long)finfo->complete_path_size));

					success = FALSE;
					break;
				}

				if(name_len == 0)
				{
					SHOWMSG("name length == 0 (skipping it)");

					success = FALSE;
					break;
				}

				finfo->ctime		= date_dos2unix (WVAL (p, 6), WVAL (p, 4));
				finfo->atime		= date_dos2unix (WVAL (p, 10), WVAL (p, 8));
				finfo->mtime		= date_dos2unix (WVAL (p, 14), WVAL (p, 12));
				finfo->wtime		= finfo->mtime;
				finfo->size_low		= DVAL (p, 16);
				finfo->size_high	= DVAL (p, 16);
				finfo->attr			= WVAL (p, 24);

				if(server->unicode_enabled)
				{
					copy_utf16le_to_latin1(server, finfo->complete_path, finfo->complete_path_size, name, name_len);
				}
				else
				{
					memcpy(finfo->complete_path, name, name_len);
					finfo->complete_path[name_len] = '\0';
				}

				finfo->len = name_len;

				D(("name = '%s', length=%ld, size=%ld",escape_name(finfo->complete_path),name_len,name_size));

				#if DEBUG
				{
					struct tm tm;

					seconds_to_tm(finfo->mtime,&tm);
					D(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->ctime,&tm);
					D(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->atime,&tm);
					D(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->wtime,&tm);
					D(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
				}
				#endif /* DEBUG */
			}

			break;

		case SMB_FILE_BOTH_DIRECTORY_INFO:

			SHOWMSG("SMB_FILE_BOTH_DIRECTORY_INFO");

			(*entry_length_ptr) = WVAL (p, 0);

			if (finfo != NULL)
			{
				dword size_low,size_high;
				int name_size;
				int name_len;

				p += 4; /* next entry offset */

				p += 4; /* fileindex */

				finfo->ctime = convert_long_date_to_time_t(p);
				p += 8;

				finfo->atime = convert_long_date_to_time_t(p);
				p += 8;

				finfo->wtime = convert_long_date_to_time_t(p);
				p += 8;

				finfo->mtime = convert_long_date_to_time_t(p);
				p += 8;

				/* If the modification time is not set, try to
				 * substitute the write time for it.
				 */
				if(finfo->mtime == 0)
					finfo->mtime = finfo->wtime;

				size_low	= DVAL (p, 0);
				size_high	= DVAL (p, 4);
				p += 8;

				finfo->size_low = size_low;
				finfo->size_high = size_high;

				p += 8; /* alloc size */

				finfo->attr = DVAL (p, 0);
				p += 4;

				name_size = DVAL (p, 0);
				p += 4;

				/* Skip directory entries whose names we cannot store. */
				if(name_size == 0)
				{
					SHOWMSG("name is empty");

					success = FALSE;
					break;
				}

				SHOWVALUE(name_size);

				p += 4; /* EA size */

				p += 1; /* short name length */
				p += 1; /* reserved */

				p += 12*2; /* short name (12 WCHAR characters) */

				/* Figure out how long the string really is. It's
				 * supposed to be NUL-terminated.
				 */
				if(server->unicode_enabled)
					name_len = strnlen_utf16(p, name_size);
				else
					name_len = strnlen(p, name_size);

				SHOWVALUE(name_len);

				/* Skip directory entries whose names we cannot store. */
				if(name_len >= (int)finfo->complete_path_size)
				{
					D(("name length >= %lu (skipping it)", (unsigned long)finfo->complete_path_size));

					success = FALSE;
					break;
				}

				if(name_len == 0)
				{
					SHOWMSG("name length == 0 (skipping it)");

					success = FALSE;
					break;
				}

				if(server->unicode_enabled)
				{
					copy_utf16le_to_latin1(server, finfo->complete_path, finfo->complete_path_size, p, name_len);
				}
				else
				{
					memcpy(finfo->complete_path, p, name_len);
					finfo->complete_path[name_len] = '\0';
				}

				finfo->len = name_len;

				D(("name = '%s', length=%ld, size=%ld",escape_name(finfo->complete_path),name_len,name_size));

				#if DEBUG
				{
					struct tm tm;

					seconds_to_tm(finfo->mtime,&tm);
					D(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->ctime,&tm);
					D(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->atime,&tm);
					D(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
					seconds_to_tm(finfo->wtime,&tm);
					D(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
				}
				#endif /* DEBUG */
			}

			break;

		/* This should never happen. */
		default:

			(*entry_length_ptr) = 0;

			success = FALSE;
			break;
	}

	D(("entry_length = %ld",(*entry_length_ptr)));

	RETURN(success);
	return(success);
}

static int
smb_proc_readdir_long (
	struct smb_server *server,
	const char *path,
	dircache_t * dircache,
	int * end_of_search_ptr,
	int * error_ptr)
{
	int max_matches;

	int info_level = server->protocol < PROTOCOL_NT1 ? SMB_INFO_STANDARD : SMB_FILE_BOTH_DIRECTORY_INFO;

	char *p;
	int i;
	int is_first;
	int total_count = 0;

	char *resp_data = NULL;
	char *resp_param = NULL;
	int resp_data_len = 0;
	int resp_param_len = 0;

	int attribute = SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_DIRECTORY;
	int result = 0;

	int ff_searchcount;
	int ff_end_of_search = 0;
	int ff_dir_handle = -1;
	int ff_resume_key = 0;
	int loop_count = 0;

	unsigned char *outbuf = server->transmit_buffer;

	struct smb_dirent * entry;

	const int path_len = strlen(path);
	const int pattern_len = path_len + 2;
	const int pattern_size = (server->unicode_enabled) ? 2 * (pattern_len + 1) : pattern_len + 1;
	char *pattern;

	int entry_length;

	ENTER();

	pattern = malloc (pattern_len+1);
	if (pattern == NULL)
	{
		SHOWMSG("Memory allocation failed");

		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memcpy(pattern,path,path_len);
	memcpy(&pattern[path_len],"\\*",3); /* This includes the terminating NUL. */

	SHOWMSG("SMB call readdir_long");
	D(("         pattern = '%s'", escape_name(pattern)));

	resp_param = NULL;
	resp_data = NULL;

	if(dircache->sid == -1 && dircache->close_sid != -1)
	{
		int sid = dircache->close_sid;

		D(("closing previous find-first/find-next session with sid=0x%04lx", sid));

		dircache->close_sid = -1;

		smb_setup_header (server, SMBfindclose, 1, 0);
		WSET (server->transmit_buffer, smb_vwv0, sid);

		smb_request_ok (server, SMBfindclose, 0, 0, error_ptr);
	}

 retry:

	if(dircache->sid == -1)
	{
		is_first = TRUE;

		ff_dir_handle = -1;
		ff_resume_key = 0;

		SHOWMSG("start scanning from the top");
	}
	else
	{
		is_first = FALSE;

		ff_dir_handle = dircache->sid;
		ff_resume_key = dircache->resume_key;

		D(("trying to resume scanning with sid=0x%04lx and resume_key=0x%08lx", ff_dir_handle, ff_resume_key));
	}

	total_count = 0;
	ff_end_of_search = 0;

	entry = get_first_dircache_entry(dircache);

	while (entry != NULL && ff_end_of_search == 0)
	{
		if (++loop_count > 200)
		{
			SHOWMSG("Looping in FIND_NEXT???");

			(*error_ptr) = error_looping_in_find_next;

			result = -1;
			goto out;
		}

		memset (outbuf, 0, sizeof(word) * smb_setup1);

		ASSERT( smb_payload_size(server, 15, 3 + 12 + pattern_size) >= 0 );

		smb_setup_header (server, SMBtrans2, 15, 3 + 12 + pattern_size);

		WSET (outbuf, smb_tpscnt, 12 + pattern_size);						/* TotalParameterCount */
		WSET (outbuf, smb_tdscnt, 0);										/* TotalDataCount */
		WSET (outbuf, smb_mprcnt, 10);										/* MaxParameterCount */
		WSET (outbuf, smb_mdrcnt, server->max_recv);						/* MaxDataCount */
		WSET (outbuf, smb_msrcnt, 0);										/* MaxSetupCount+Reserved1 */
		WSET (outbuf, smb_flags, 0);										/* Flags */
		DSET (outbuf, smb_timeout, 0);										/* Timeout */
																			/* Reserved2 */
		WSET (outbuf, smb_pscnt, WVAL (outbuf, smb_tpscnt));				/* ParameterCount */
		WSET (outbuf, smb_psoff, ((SMB_BUF (outbuf) + 3) - outbuf) - NETBIOS_HEADER_SIZE);	/* ParameterOffset */
		WSET (outbuf, smb_dscnt, 0);										/* DataCount */
		WSET (outbuf, smb_dsoff, 0);										/* DataOffset */
		WSET (outbuf, smb_suwcnt, 1);										/* SetupCount+Reserved3 */
		WSET (outbuf, smb_setup0, is_first ? TRANSACT2_FINDFIRST : TRANSACT2_FINDNEXT);	/* Setup[0] */

		p = SMB_BUF (outbuf);
		(*p++) = '\0'; /* put in a null smb_name */

		/* Align the parameter data to a 4-byte boundary. */
		(*p++) = '\0';
		(*p++) = '\0';

		max_matches = get_dircache_entries_available(dircache);

		ASSERT( max_matches > 0 );

		D(("max_matches=%ld", max_matches));

		if (is_first)
		{
			SHOWMSG("first match");

			WSET (p, 0, attribute); /* attribute */
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, SMB_FIND_CLOSE_AT_EOS|SMB_FIND_RETURN_RESUME_KEYS|SMB_FIND_CONTINUE_FROM_LAST);
			WSET (p, 6, info_level);
			DSET (p, 8, 0); /* return every entry there is */
		}
		else
		{
			D(("next match; ff_dir_handle=0x%04lx ff_resume_key=0x%08lx pattern='%s'", ff_dir_handle, ff_resume_key, escape_name(pattern)));

			WSET (p, 0, ff_dir_handle);
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, info_level);
			DSET (p, 6, ff_resume_key);
			WSET (p, 10, SMB_FIND_CLOSE_AT_EOS|SMB_FIND_RETURN_RESUME_KEYS|SMB_FIND_CONTINUE_FROM_LAST);
		}

		p += 12;

		if(server->unicode_enabled)
		{
			copy_latin1_to_utf16le(server, p,pattern_size,pattern,pattern_len);
		}
		else
		{
			memcpy (p, pattern, pattern_len);
			p[pattern_len] = '\0';
		}

		result = smb_trans2_request (server, SMBtrans2, &resp_data_len, &resp_param_len, &resp_data, &resp_param, error_ptr);

		D(("smb_trans2_request returns %ld", result));

		/* If an error was flagged, check first if it's a protocol
		 * error which we could handle below. Otherwise, try again.
		 */
		if (result < 0 && (*error_ptr) != error_check_smb_error)
		{
			if (smb_retry (server))
				goto retry;

			SHOWMSG("got error from trans2_request");
			goto out;
		}

		/* Apparently, there is a bug in Windows 95 and friends which
		 * causes the directory read attempt to fail if you're asking
		 * for too much data too fast...
		 */
		if(server->rcls == ERRSRV && server->err == ERRerror)
		{
			SHOWMSG("ouch; delaying and retrying");

			PROFILE_OFF();

			Delay(TICKS_PER_SECOND / 5);

			PROFILE_ON();

			continue;
		}

		/* If there's a protocol error, stop and abort. */
		if (server->rcls != 0)
		{
			D(("server->rcls = %ld err = %ld",server->rcls, server->err));

			smb_printerr (server->rcls, server->err);

			(*error_ptr) = error_check_smb_error;

			result = -1;
			goto out;
		}

		/* Bail out if this is empty. */
		ASSERT( resp_param != NULL );

		if (resp_param == NULL)
		{
			SHOWMSG("no response parameters to process; stopping the search for now");
			break;
		}

		/* parse out some important return info */
		p = resp_param;

		if (is_first)
		{
			ASSERT( resp_param_len >= 6 );

			if(resp_param_len < 6)
			{
				SHOWMSG("not enough response parameter data to process; stopping the search for now");
				break;
			}

			/* This is the "search identifier" which allows us to
			 * keep scanning this directory until we hit the
			 * last entry.
			 */
			ff_dir_handle = WVAL (p, 0);

			ff_searchcount = WVAL (p, 2);
			ff_end_of_search = WVAL (p, 4);
		}
		else
		{
			ASSERT( resp_param_len >= 4 );

			if(resp_param_len < 4)
			{
				SHOWMSG("not enough response parameter data to process; stopping the search for now");
				break;
			}

			ff_searchcount = WVAL (p, 0);
			ff_end_of_search = WVAL (p, 2);
		}

		ASSERT( ff_searchcount <= max_matches );

		D(("received %ld entries (end of search = %s)",ff_searchcount, ff_end_of_search ? "yes" : "no"));

		if (ff_searchcount == 0)
		{
			SHOWMSG("no further entries available; stopping the search for now");
			break;
		}

		/* Bail out if this is empty. */
		ASSERT( resp_data != NULL );

		if (resp_data == NULL)
		{
			SHOWMSG("no directory data to process; stopping the search for now");
			break;
		}

		/* Now we are ready to parse smb directory entries. */
		for (i = 0, p = resp_data, entry_length = 0 ;
		     i < ff_searchcount && entry != NULL && p < &resp_data[resp_data_len];
		     i++, p += entry_length)
		{
			ff_resume_key = DVAL(p, 0);

			D(("sid=0x%04lx, resume_key=0x%08lx", ff_dir_handle, ff_resume_key));

			/* Skip this entry if we cannot decode the name. This could happen
			 * if the name will no fit into the buffer.
			 */
			if(!smb_decode_long_dirent (server, p, entry, info_level, &entry_length))
			{
				if(entry_length == 0)
				{
					SHOWMSG("no more entries available; stopping.");
					break;
				}

				D(("skipped entry; total_count = %ld, i = %ld", total_count, i));

				continue;
			}

			entry = get_next_dircache_entry(dircache);

			ASSERT( entry != NULL || i+1 == ff_searchcount );

			if(entry == NULL && i+1 < ff_searchcount)
				SHOWMSG("ran out of directory cache entries, which should never happen...");

			total_count++;
		}

		if (resp_data != NULL)
		{
			free (resp_data);
			resp_data = NULL;
		}

		if (resp_param != NULL)
		{
			free (resp_param);
			resp_param = NULL;
		}

		is_first = FALSE;

		if (ff_searchcount > 0)
			loop_count = 0;
	}

	result = total_count;

 out:

	/* finished: not needed any more */
	if (pattern != NULL)
		free (pattern);

	if (resp_data != NULL)
		free (resp_data);

	if (resp_param != NULL)
		free (resp_param);

	(*end_of_search_ptr) = ff_end_of_search;

	if(result >= 0)
	{
		if(ff_end_of_search)
		{
			SHOWMSG("not resuming this scan operation");

			dircache->sid = -1;
			dircache->resume_key = 0;
		}
		else
		{
			dircache->sid = ff_dir_handle;
			dircache->resume_key = ff_resume_key;
		}
	}
	else
	{
		SHOWMSG("not resuming this scan operation");

		dircache->sid = -1;
		dircache->resume_key = 0;
	}

	RETURN(result);
	return(result);
}

int
smb_proc_readdir (
	struct smb_server *server,
	const char *path,
	dircache_t * dircache,
	int * end_of_search_ptr,
	int * error_ptr)
{
	int result;

	if (server->protocol >= PROTOCOL_LANMAN2)
		result = smb_proc_readdir_long (server, path, dircache, end_of_search_ptr, error_ptr);
	else
		result = smb_proc_readdir_short (server, path, dircache, end_of_search_ptr, error_ptr);

	return result;
}

int
smb_proc_getattr_core (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr)
{
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	int path_size;

	D(("path='%s'", escape_name(path)));

	if(server->unicode_enabled)
	{
		// Tygre 2015/05/29: Size in UTF16
		// The size is that of the bytes stored,
		// plus the Latin1 path as prefix, not
		// two bytes per char anymore in UTF16.
		path_size = size_utf16le_of_latin1(server, path);
		if(-1 == path_size)
		{
			// Default size
			path_size = 2 * (len + 1);
		}
	}
	else
	{
		path_size = len + 1;
	}

	ASSERT( smb_payload_size(server, 0, 1 + path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBgetatr, 0, 1 + path_size);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		copy_latin1_to_utf16le(server, p, path_size, path, len);
	}
	else
	{
		smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBgetatr, 10, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			goto retry;
		}
		else
		{
			goto out;
		}
	}

	entry->attr = WVAL (buf, smb_vwv0);

	/* The server only tells us just the wtime */
	entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc(DVAL (buf, smb_vwv1)); /* Note: this is UTIME, and should be the server's local time. */

	#if DEBUG
	{
		struct tm tm_utc;
		struct tm tm_local;

		seconds_to_tm(entry->mtime,&tm_utc);

		D(("modification time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
			tm_utc.tm_year + 1900,
			tm_utc.tm_mon+1,
			tm_utc.tm_mday,
			tm_utc.tm_hour,
			tm_utc.tm_min,
			tm_utc.tm_sec));

		seconds_to_tm(DVAL (buf, smb_vwv1),&tm_local);

		D(("                    %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
			tm_local.tm_year + 1900,
			tm_local.tm_mon+1,
			tm_local.tm_mday,
			tm_local.tm_hour,
			tm_local.tm_min,
			tm_local.tm_sec));
	}
	#endif /* DEBUG */

	entry->size_low = DVAL (buf, smb_vwv3);
	entry->size_high = 0;

 out:

	return result;
}

int
smb_query_path_information(
	struct smb_server *server,
	const char *path,
	int len,
	int fid,
	struct smb_dirent *entry,
	int * error_ptr)
{
	unsigned char *outbuf = server->transmit_buffer;
	dword ext_file_attributes;
	dword end_of_file_low;
	dword end_of_file_high;
	int is_directory;
	dword file_name_length;
	int parameter_count;
	const char * file_name;
	char * p;
	int result;
	char *resp_data = NULL;
	int resp_data_len = 0;
	int path_size;

 retry:

	if(len > 0)
	{
		if(server->unicode_enabled)
			path_size = 2 * (len+1);
		else
			path_size = len+1;

		parameter_count = 2 + 4 + path_size;
	}
	else
	{
		parameter_count = 2 + 2;
		path_size = 0;
	}

	ASSERT( smb_payload_size(server, 15, 3 + parameter_count) >= 0 );

	smb_setup_header (server, SMBtrans2, 15, 3 + parameter_count);

	WSET (outbuf, smb_tpscnt, parameter_count);							/* TotalParameterCount */
	WSET (outbuf, smb_tdscnt, 0);										/* TotalDataCount */
	WSET (outbuf, smb_mprcnt, 0);										/* MaxParameterCount */
	WSET (outbuf, smb_mdrcnt, server->max_recv);						/* MaxDataCount */
	WSET (outbuf, smb_msrcnt, 0);										/* MaxSetupCount+Reserved1 */
	WSET (outbuf, smb_flags, 0);										/* Flags */
	DSET (outbuf, smb_timeout, 0);										/* Timeout */
																		/* Reserved2 */
	WSET (outbuf, smb_pscnt, WVAL (outbuf, smb_tpscnt));				/* ParameterCount */
	WSET (outbuf, smb_psoff, ((SMB_BUF (outbuf) + 3) - outbuf) - NETBIOS_HEADER_SIZE);	/* ParameterOffset */
	WSET (outbuf, smb_dscnt, 0);										/* DataCount */
	WSET (outbuf, smb_dsoff, 0);										/* DataOffset */
	WSET (outbuf, smb_suwcnt, 1);										/* SetupCount+Reserved3 */
	WSET (outbuf, smb_setup0, len > 0 ? TRANSACT2_QPATHINFO : TRANSACT2_QFILEINFO);	/* Setup[0] */

	p = SMB_BUF (outbuf);

	/* Align to a 4-byte-boundary. */
	(*p++) = '\0';
	(*p++) = '\0';
	(*p++) = '\0';

	if(len > 0)
	{
		WSET (p, 0, SMB_QUERY_FILE_ALL_INFO);
		DSET (p, 2, 0);

		p += 2 + 4;

		if(server->unicode_enabled)
		{
			copy_latin1_to_utf16le(server, p,path_size,path,len);
		}
		else
		{
			memcpy(p,path,len);
			p[len] = '\0';
		}
	}
	else
	{
		WSET (p, 0, fid);
		WSET (p, 2, SMB_QUERY_FILE_ALL_INFO);
	}

	result = smb_trans2_request (server, SMBtrans2, &resp_data_len, NULL, &resp_data, NULL, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			/* We don't need the file id? */
			if (len > 0)
			{
				goto retry;
			}
			/* We do need the file id. */
			else if (reopen_entry(server,entry,NULL) == 0)
			{
				fid = entry->fileid;
				goto retry;
			}
		}

		goto out;
	}

	if(server->rcls != 0)
	{
		(*error_ptr) = error_check_smb_error;

		result = -1;
		goto out;
	}

	ASSERT( resp_data != NULL );

	p = resp_data;

	entry->ctime = convert_long_date_to_time_t(p);
	p += 2 * sizeof(dword); /* CreateTime */

	entry->atime = convert_long_date_to_time_t(p);
	p += 2 * sizeof(dword); /* LastAccessTime */

	entry->wtime = convert_long_date_to_time_t(p);
	p += 2 * sizeof(dword); /* LastWriteTime */

	entry->mtime = convert_long_date_to_time_t(p);
	p += 2 * sizeof(dword); /* LastChangeTime */

	p = smb_decode_dword(p, &ext_file_attributes);
	entry->attr = ext_file_attributes;

	p += sizeof(dword); /* Reserved */

	p += 2 * sizeof(dword); /* AllocationSize */

	p = smb_decode_dword(p, &end_of_file_low);
	p = smb_decode_dword(p, &end_of_file_high);

	entry->size_low = end_of_file_low;
	entry->size_high = end_of_file_high;

	p += sizeof(dword); /* Number of links */

	p += 1; /* Delete pending */

	is_directory = (*p);
	p += 1; /* Directory */

	p += sizeof(word); /* Reserved */

	p += sizeof(dword); /* Extended attribute size */

	/* File name follows the length field. */
	file_name = smb_decode_dword(p, &file_name_length);

	#if DEBUG
	{
		TEXT name[SMB_MAXNAMELEN+1];
		struct tm tm;
		QUAD entry_size_quad;

		/* Let's show what the name of the object in
		 * question is supposed to look like. The
		 * text is provided as 16 bit characters,
		 * even if Unicode mode is not enabled.
		 */
		copy_utf16le_to_latin1(server, name, sizeof(name), file_name, file_name_length / sizeof(word));

		entry_size_quad.Low		= entry->size_low;
		entry_size_quad.High	= entry->size_high;

		seconds_to_tm(entry->mtime,&tm);
		D(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
		seconds_to_tm(entry->ctime,&tm);
		D(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
		seconds_to_tm(entry->atime,&tm);
		D(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
		seconds_to_tm(entry->wtime,&tm);
		D(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
		D(("size = %s (0x%08lx%08lx)",convert_quad_to_string(&entry_size_quad),entry->size_high,entry->size_low));
		D(("attr = 0x%08lx",entry->attr));
		D(("name = '%s' (length in bytes = %ld)",escape_name(name),file_name_length));
	}
	#endif /* DEBUG */

 out:

	if(resp_data != NULL)
		free(resp_data);

	return result;
}

/* smb_proc_getattrE: entry->fid must be valid */
int
smb_proc_getattrE (struct smb_server *server, struct smb_dirent *entry, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

 retry:

	smb_setup_header (server, SMBgetattrE, 1, 0);
	WSET (buf, smb_vwv0, entry->fileid);

	result = smb_request_ok (server, SMBgetattrE, 11, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
		else
			goto out;
	}

	entry->ctime = date_dos2unix (WVAL (buf, smb_vwv1), WVAL (buf, smb_vwv0));
	entry->atime = date_dos2unix (WVAL (buf, smb_vwv3), WVAL (buf, smb_vwv2));
	entry->mtime = date_dos2unix (WVAL (buf, smb_vwv5), WVAL (buf, smb_vwv4));
	entry->wtime = entry->mtime;

	entry->size_low		= DVAL (buf, smb_vwv6);
	entry->size_high	= 0;

	entry->attr = WVAL (buf, smb_vwv10);

	#if DEBUG
	{
		struct tm tm;

		seconds_to_tm(entry->ctime,&tm);
		D(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->atime,&tm);
		D(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->mtime,&tm);
		D(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->wtime,&tm);
		D(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

 out:

	return result;
}

int
smb_set_file_information(struct smb_server *server, struct smb_dirent *entry, const QUAD * const size_quad, int * error_ptr)
{
	unsigned char *outbuf = server->transmit_buffer;
	int data_size;
	char * p;
	int result;
	QUAD change_time_quad;

 retry:

	data_size = (size_quad == NULL) ? 40 : 8;

	ASSERT( smb_payload_size(server, 15, 3 + 6 + 2 + data_size) >= 0 );

	smb_setup_header (server, SMBtrans2, 15, 3 + 6 + 2 + data_size);

	WSET (outbuf, smb_tpscnt, 6);										/* TotalParameterCount */
	WSET (outbuf, smb_tdscnt, data_size);								/* TotalDataCount */
	WSET (outbuf, smb_mprcnt, 0);										/* MaxParameterCount */
	WSET (outbuf, smb_mdrcnt, server->max_recv);						/* MaxDataCount */
	WSET (outbuf, smb_msrcnt, 0);										/* MaxSetupCount+Reserved1 */
	WSET (outbuf, smb_flags, 0);										/* Flags */
	DSET (outbuf, smb_timeout, 0);										/* Timeout */
																		/* Reserved2 */
	WSET (outbuf, smb_pscnt, WVAL (outbuf, smb_tpscnt));				/* ParameterCount */
	WSET (outbuf, smb_psoff, ((SMB_BUF (outbuf) + 3) - outbuf) - NETBIOS_HEADER_SIZE);	/* ParameterOffset */
	WSET (outbuf, smb_dscnt, WVAL (outbuf, smb_tdscnt));				/* DataCount */
	WSET (outbuf, smb_dsoff, WVAL (outbuf, smb_psoff) + 6+2);			/* DataOffset */
	WSET (outbuf, smb_suwcnt, 1);										/* SetupCount+Reserved3 */
	WSET (outbuf, smb_setup0, TRANSACT2_SETFILEINFO);					/* Setup[0] */

	p = SMB_BUF (outbuf);

	/* Align to a 4-byte-boundary. */
	(*p++) = '\0';
	(*p++) = '\0';
	(*p++) = '\0';

	WSET (p, 0, entry->fileid);
	WSET (p, 2, size_quad == NULL ? SMB_SET_FILE_BASIC_INFO : SMB_SET_FILE_END_OF_FILE_INFO);
	WSET (p, 4, 0);

	p += 6;

	/* Align to a 4-byte-boundary. */
	(*p++) = '\0';
	(*p++) = '\0';

	if(size_quad == NULL)
	{
		/* Creation time (no change) */
		DSET(p, 0, 0);
		DSET(p, 4, 0);

		/* Last access time (no change) */
		DSET(p, 8, 0);
		DSET(p, 12, 0);

		/* Note that we update both mtime and wtime of the
		 * directory and not just mtime because some Samba
		 * versions will end up setting the mtime of the
		 * directory entry to the time given as the wtime
		 * value and ignore the mtime value. This happens
		 * even if the wtime value is given as zero and the
		 * mtime value is non-zero.
		 */
		D(("entry->mtime = %lu",entry->mtime));

		convert_time_t_to_long_date(entry->mtime,&change_time_quad);

		/* Last write time */
		DSET(p, 16, change_time_quad.Low);
		DSET(p, 20, change_time_quad.High);

		/* Change time */
		DSET(p, 24, change_time_quad.Low);
		DSET(p, 28, change_time_quad.High);

		/* Extended file attributes */
		DSET(p, 32, entry->attr);

		/* Reserved */
		DSET(p, 36, 0);
	}
	else
	{
		/* End of file */
		DSET(p, 0, size_quad->Low);
		DSET(p, 4, size_quad->High);
	}

	result = smb_trans2_request (server, SMBtrans2, NULL, NULL, NULL, NULL, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
		{
			if(reopen_entry(server,entry,NULL) == 0)
				goto retry;
		}

		SHOWMSG("that didn't work.");
		goto out;
	}

	if(server->rcls != 0)
	{
		(*error_ptr) = error_check_smb_error;

		result = -1;
	}

 out:

	return result;
}

/* In core protocol, there is only 1 time to be set, we use
 * entry->mtime, to make touch work.
 */
int
smb_proc_setattr_core (struct smb_server *server, const char *path, int len, const struct smb_dirent *new_finfo, int * error_ptr)
{
	dword local_time;
	char *p;
	char *buf = server->transmit_buffer;
	int result;
	int path_size;
	dword attr;

	/* Don't do anything if mtime is unset. */
	if(new_finfo->mtime == 0 || new_finfo->mtime == (time_t)-1)
		return(0);

	if(server->unicode_enabled)
	{
		// Tygre 2015/05/29: Size in UTF16
		// The size is that of the bytes stored,
		// plus the Latin1 path as prefix, not
		// two bytes per char anymore in UTF16.
		path_size = size_utf16le_of_latin1(server, path);
		if(-1 == path_size)
		{
			// Default size
			path_size = 2 * (len + 1);
		}
	}
	else
	{
		path_size = len + 1;
	}

	ASSERT( smb_payload_size(server, 8, 1 + path_size) >= 0 );

	/* We cache these because if the connection needs to be
	 * reestablished, the direntry values will all get
	 * overwritten.
	 */
	attr = new_finfo->attr;

	local_time = utc2local(new_finfo->mtime); /* Note: this is UTIME, and should be the server's local time. */

	#if DEBUG
	{
		struct tm tm_local;
		struct tm tm_utc;

		seconds_to_tm(new_finfo->mtime,&tm_utc);

		D(("modification time = %ld-%02ld-%02ld %02ld:%02ld:%02ld (UTC)",
			tm_utc.tm_year + 1900,
			tm_utc.tm_mon+1,
			tm_utc.tm_mday,
			tm_utc.tm_hour,
			tm_utc.tm_min,
			tm_utc.tm_sec));

		seconds_to_tm(local_time,&tm_local);

		D(("                    %ld-%02ld-%02ld %02ld:%02ld:%02ld (local)",
			tm_local.tm_year + 1900,
			tm_local.tm_mon+1,
			tm_local.tm_mday,
			tm_local.tm_hour,
			tm_local.tm_min,
			tm_local.tm_sec));
	}
	#endif /* DEBUG */

 retry:

	p = smb_setup_header (server, SMBsetatr, 8, 1 + path_size);
	WSET (buf, smb_vwv0, attr);
	DSET (buf, smb_vwv1, local_time);
	WSET (buf, smb_vwv3, 0);
	WSET (buf, smb_vwv4, 0);
	WSET (buf, smb_vwv5, 0);
	WSET (buf, smb_vwv6, 0);
	WSET (buf, smb_vwv7, 0);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A NUL-terminated string follows. */
		p += copy_latin1_to_utf16le(server, p, path_size, path, len);
	}
	else
	{
		p = smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBsetatr, 0, 0, error_ptr);
	if (result < 0)
	{
		if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			goto retry;
	}

	return result;
}

int
smb_proc_setattrE (struct smb_server *server, word fid, struct smb_dirent *new_entry, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	word date, time_value;
	time_t ctime, atime, mtime;
	int num_changes;
	int result;

	/* We cache these because if the connection needs to be
	 * reestablished, the direntry values will all get
	 * overwritten.
	 */
	ctime = new_entry->ctime;
	atime = new_entry->atime;
	mtime = new_entry->mtime;

 retry:

	smb_setup_header (server, SMBsetattrE, 7, 0);

	WSET (buf, smb_vwv0, fid);

	num_changes = 0;

	if(ctime != 0 && ctime != (time_t)-1)
	{
		date_unix2dos (ctime, &time_value, &date);
		num_changes++;
	}
	else
	{
		date = time_value = 0;
	}

	WSET (buf, smb_vwv1, date);
	WSET (buf, smb_vwv2, time_value);

	if(atime != 0 && atime != (time_t)-1)
	{
		date_unix2dos (atime, &time_value, &date);
		num_changes++;
	}
	else
	{
		date = time_value = 0;
	}

	WSET (buf, smb_vwv3, date);
	WSET (buf, smb_vwv4, time_value);

	if(mtime != 0 && mtime != (time_t)-1)
	{
		date_unix2dos (mtime, &time_value, &date);
		num_changes++;
	}
	else
	{
		date = time_value = 0;
	}

	WSET (buf, smb_vwv5, date);
	WSET (buf, smb_vwv6, time_value);

	/* Do we actually have to change anything at all? */
	if(num_changes > 0)
	{
		result = smb_request_ok (server, SMBsetattrE, 0, 0, error_ptr);
		if (result < 0)
		{
			if ((*error_ptr) != error_check_smb_error && smb_retry (server))
			{
				if(reopen_entry(server,new_entry,NULL) == 0)
				{
					fid = new_entry->fileid;
					goto retry;
				}
			}

			SHOWMSG("that didn't work.");
		}
	}
	else
	{
		result = 0;
	}

	return result;
}

int
smb_proc_dskattr (struct smb_server *server, struct smb_dskattr *attr, int * error_ptr)
{
	char *resp_data = NULL;
	int resp_data_len = 0;

	int result;
	char *p;

 retry:

	if (!server->prefer_core_protocol && server->protocol >= PROTOCOL_NT1)
	{
		unsigned char *outbuf = server->transmit_buffer;
		dword total_allocation_units;
		dword total_free_allocation_units;
		dword sectors_per_allocation_unit;
		dword bytes_per_sector;

		ASSERT( smb_payload_size(server, 15, 3 + 2) >= 0 );

		smb_setup_header (server, SMBtrans2, 15, 3 + 2);

		WSET (outbuf, smb_tpscnt, 2);										/* TotalParameterCount */
		WSET (outbuf, smb_tdscnt, 0);										/* TotalDataCount */
		WSET (outbuf, smb_mprcnt, 0);										/* MaxParameterCount */
		WSET (outbuf, smb_mdrcnt, server->max_recv);						/* MaxDataCount */
		WSET (outbuf, smb_msrcnt, 0);										/* MaxSetupCount+Reserved1 */
		WSET (outbuf, smb_flags, 0);										/* Flags */
		DSET (outbuf, smb_timeout, 0);										/* Timeout */
																			/* Reserved2 */
		WSET (outbuf, smb_pscnt, WVAL (outbuf, smb_tpscnt));				/* ParameterCount */
		WSET (outbuf, smb_psoff, ((SMB_BUF (outbuf) + 3) - outbuf) - NETBIOS_HEADER_SIZE);	/* ParameterOffset */
		WSET (outbuf, smb_dscnt, 0);										/* DataCount */
		WSET (outbuf, smb_dsoff, 0);										/* DataOffset */
		WSET (outbuf, smb_suwcnt, 1);										/* SetupCount+Reserved3 */
		WSET (outbuf, smb_setup0, TRANSACT2_QFSINFO);						/* Setup[0] */

		p = SMB_BUF (outbuf);

		/* Align to a 4-byte-boundary. */
		(*p++) = '\0';
		(*p++) = '\0';
		(*p++) = '\0';

		WSET (p, 0, SMB_QUERY_FS_SIZE_INFO);

		result = smb_trans2_request (server, SMBtrans2, &resp_data_len, NULL, &resp_data, NULL, error_ptr);
		if (result < 0)
		{
			if ((*error_ptr) != error_check_smb_error && smb_retry (server))
				goto retry;

			goto out;
		}

		if(server->rcls != 0)
		{
			(*error_ptr) = error_check_smb_error;

			result = -1;
			goto out;
		}

		ASSERT( resp_data != NULL );

		p = resp_data;

		p = smb_decode_dword (p, &total_allocation_units);
		p += sizeof(dword);

		SHOWVALUE(total_allocation_units);

		p = smb_decode_dword (p, &total_free_allocation_units);
		p += sizeof(dword);

		SHOWVALUE(total_free_allocation_units);

		p = smb_decode_dword (p, &sectors_per_allocation_unit);
		(void) smb_decode_dword (p, &bytes_per_sector);

		SHOWVALUE(bytes_per_sector);
		SHOWVALUE(sectors_per_allocation_unit);

		attr->total = total_allocation_units;
		attr->free = total_free_allocation_units;

		attr->blocksize = bytes_per_sector;
		attr->allocblocks = sectors_per_allocation_unit;
	}
	else
	{
		word total_units;
		word sectors_per_unit;
		word bytes_per_sector;
		word free_units;

		ASSERT( smb_payload_size(server, 0, 0) >= 0 );

		smb_setup_header (server, SMBdskattr, 0, 0);

		result = smb_request_ok (server, SMBdskattr, 5, 0, error_ptr);
		if (result < 0)
		{
			if ((*error_ptr) != error_check_smb_error && smb_retry (server))
				goto retry;

			goto out;
		}

		p = SMB_VWV (server->transmit_buffer);
		p = smb_decode_word (p, &total_units);
		p = smb_decode_word (p, &sectors_per_unit);
		p = smb_decode_word (p, &bytes_per_sector);
		(void) smb_decode_word (p, &free_units);

		attr->total			= total_units;
		attr->allocblocks	= sectors_per_unit;
		attr->blocksize		= bytes_per_sector;
		attr->free			= free_units;
	}

 out:

	if (resp_data != NULL)
		free (resp_data);

	return result;
}

/*****************************************************************************
 *
 *  Mount/umount operations.
 *
 ****************************************************************************/
struct smb_prots
{
	enum smb_protocol	prot;
	const char *		name;
};

static int
smb_proc_reconnect (struct smb_server *server, int * error_ptr)
{
	static const struct smb_prots prots[] =
	{
		{PROTOCOL_CORE,		"PC NETWORK PROGRAM 1.0"},	/* Core Protocol */
		{PROTOCOL_COREPLUS,	"MICROSOFT NETWORKS 1.03"},	/* CorePlus */
		{PROTOCOL_LANMAN1,	"MICROSOFT NETWORKS 3.0"},	/* DOS LAN Manager 1.0 */
		{PROTOCOL_LANMAN1,	"LANMAN1.0"},				/* LAN Manager 1.0 */
		{PROTOCOL_LANMAN2,	"LM1.2X002"},				/* LAN Manager 2.0 */
		{PROTOCOL_NT1,		"NT LM 0.12"},				/* NT LAN Manager */
		{PROTOCOL_NT1,		"NT LANMAN 1.0"},
	};

	/* Add a bit of fudge to account for the NetBIOS session
	 * header and whatever else might show up. How much space is
	 * required breaks down as follows:
	 *
	 *  4 bytes for the NetBIOS session header
	 * 32 bytes for the SMB frame header
	 *  1 byte for the parameter count
	 *  x words (2 bytes each) for the parameters
	 *  1 word (2 bytes) for the number of bytes to transmit (payload)
	 *  y bytes to transmit (payload)
	 *
	 * The parameter count (x) and the number of bytes to
	 * transmit may vary.
	 *
	 * What follows the 4 byte NetBIOS session header must not be
	 * larger than that an unsigned 17 bit integer can hold. It should
	 * not be much larger than 65535 bytes, though, since the transmission
	 * buffer only has some extra 1024 bytes of room at the end.
	 */
	const int safety_margin = 1024;
	const int num_prots = sizeof(prots) / sizeof(prots[0]);
	const char dev[] = "A:";
	int i, plength;
	const int default_max_buffer_size = 1024; /* Space needed for first request. */
	int given_max_xmit;
	int result;
	word dialect_index;
	byte *p;
	unsigned char oem_password[24];
	int oem_password_len;
	unsigned char unicode_password[24];
	int unicode_password_len;
	char * share_name = NULL;
	byte *packet;
	dword max_buffer_size;
	int packet_size;
	int enable_unicode = 0;

	result = smb_connect (server, error_ptr);
	if (result < 0)
	{
		SHOWMSG("could not connect to server");
		goto out;
	}

	/* Unless we know better, we don't go for Unicode just yet. */
	server->unicode_enabled = FALSE;

	/* Here we assume that the connection is valid */
	server->state = CONN_VALID;

	server->max_buffer_size = default_max_buffer_size;
	SHOWVALUE(server->max_buffer_size);

	/* Minimum receive buffer size is 8000 bytes, but cannot
	 * be larger than 65535 bytes.
	 */
	if (0 < server->mount_data.given_max_xmit && server->mount_data.given_max_xmit < 8000)
		given_max_xmit = 8000;
	else if (0 < server->mount_data.given_max_xmit && server->mount_data.given_max_xmit < 65536)
		given_max_xmit = server->mount_data.given_max_xmit;
	else
		given_max_xmit = 65535;

	if (server->max_recv <= 0)
		server->max_recv = given_max_xmit;

	SHOWVALUE(server->max_recv);

	/* We need to allocate memory for the buffer which is used both
	 * for reception and transmission of messages. This means that it has
	 * to be large enough to account for both uses. The maximum
	 * transmit buffer size reported by the server may be smaller than
	 * the maximum message size which smbfs is prepared to accept, or
	 * it could be the other way round.
	 */
	packet_size = server->max_recv;
	if (packet_size < (int)server->max_buffer_size)
		packet_size = (int)server->max_buffer_size;

	SHOWVALUE(packet_size);

	if (server->transmit_buffer != NULL)
		free (server->transmit_buffer);

	server->transmit_buffer_size = packet_size;

	/* Add a bit of fudge to account for the NetBIOS session
	 * header and whatever else might show up...
	 */
	server->transmit_buffer_allocation_size = server->transmit_buffer_size + safety_margin;

	server->transmit_buffer = malloc (server->transmit_buffer_allocation_size);
	if (server->transmit_buffer == NULL)
	{
		SHOWMSG("No memory! Bailing out.");

		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	packet = server->transmit_buffer;

	/* Prepend a NetBIOS header? */
	if(!server->raw_smb)
	{
		/* Start with an RFC1002 session request packet. */
		p = packet + NETBIOS_HEADER_SIZE;

		p = smb_name_mangle (p, server->mount_data.server_name);
		p = smb_name_mangle (p, server->mount_data.client_name);

		/* Careful: the SMB packet length does not include the
		 *          size of the NetBIOS header itself.
		 */
		smb_encode_smb_length (packet, (byte *) p - (byte *) (packet + NETBIOS_HEADER_SIZE));

		packet[0] = 0x81; /* SESSION REQUEST */

		result = smb_request (server, 0, NULL, NULL, 0, error_ptr);
		if (result < 0)
		{
			SHOWMSG("Failed to send SESSION REQUEST.");
			goto out;
		}

		if (packet[0] != 0x82)
		{
			D(("Did not receive positive response (err = %lx)",packet[0]));

			#if DEBUG
			{
				smb_dump_packet (packet);
			}
			#endif /* DEBUG */

			(*error_ptr) = error_session_request_failed;

			result = -1;
			goto out;
		}

		SHOWMSG("Passed SESSION REQUEST.");
	}

	/* Now we are ready to send a SMB Negotiate Protocol packet. */
	plength = 0;
	for (i = 0; i < num_prots ; i++)
		plength += 1 + strlen (prots[i].name) + 1;

	ASSERT( smb_payload_size(server, 0, plength) >= 0 );

	smb_setup_header (server, SMBnegprot, 0, plength);

	p = SMB_BUF (packet);

	for (i = 0; i < num_prots ; i++)
		p = smb_encode_dialect (p, prots[i].name, strlen (prots[i].name));

	SHOWMSG("Request SMBnegprot...");

	result = smb_request_ok (server, SMBnegprot, 1, -1, error_ptr);
	if (result < 0)
	{
		SHOWMSG("Failure requesting SMBnegprot");
		goto out;
	}

	p = SMB_VWV (packet);

	p = smb_decode_word (p, &dialect_index);

	/* If the server does not support any of the listed
	 * dialects, ist must return a dialect index of 0xFFFF.
	 */
	if(dialect_index > num_prots || dialect_index == 0xFFFFU)
	{
		SHOWMSG("Unsupported dialect");

		(*error_ptr) = error_unsupported_dialect;

		result = -1;
		goto out;
	}

	server->protocol = prots[dialect_index].prot;

	D(("Server wants %s protocol.",prots[dialect_index].name));

	if (server->protocol > PROTOCOL_LANMAN1)
	{
		int user_len = strlen (server->mount_data.username);
		dword server_sesskey;

		/*
		D(("password = %s",server->mount_data.password));
		*/
		D(("usernam = %s",server->mount_data.username));
		D(("blkmode = %ld",WVAL (packet, smb_vwv5)));

		/* NT LAN Manager or newer. */
		if (server->protocol >= PROTOCOL_NT1)
		{
			server->security_mode = (*p++);

			SHOWMSG("NT LAN Manager or newer");

			/* Skip "max mpx count" (1 word) and "max number vcs" (1 word). */
			p += 2 * sizeof(word);

			p = smb_decode_dword(p, &max_buffer_size);
			SHOWVALUE (max_buffer_size);

			#if defined(OVERRIDE_SERVER_MAX_BUFFER_SIZE)
			{
				max_buffer_size = OVERRIDE_SERVER_MAX_BUFFER_SIZE;
			}
			#endif /* OVERRIDE_SERVER_MAX_BUFFER_SIZE */

			p = smb_decode_dword(p, &server->max_raw_size);
			SHOWVALUE (server->max_raw_size);
			p = smb_decode_dword(p, &server_sesskey);
			p = smb_decode_dword(p, &server->capabilities);

			/* Skip "system time" (1 qword) and "server time zone" (1 word). */
			p += 2 * sizeof(dword) + sizeof(word);

			server->crypt_key_length = (*p);

			SHOWVALUE(server->crypt_key_length);

			memcpy(server->crypt_key,SMB_BUF(packet),server->crypt_key_length);
		}
		/* LAN Manager 2.0 or older */
		else
		{
			word blkmode;

			SHOWMSG("LAN Manager 2.0 or older");

			server->security_mode = BVAL(packet, smb_vwv1);
			max_buffer_size = WVAL (packet, smb_vwv2);
			SHOWVALUE (max_buffer_size);

			#if defined(OVERRIDE_SERVER_MAX_BUFFER_SIZE)
			{
				max_buffer_size = OVERRIDE_SERVER_MAX_BUFFER_SIZE;
			}
			#endif /* OVERRIDE_SERVER_MAX_BUFFER_SIZE */

			/* Maximum raw read/write size is fixed to 65535 bytes. */
			server->max_raw_size = 65535;
			blkmode = WVAL (packet, smb_vwv5);
			server_sesskey = DVAL (packet, smb_vwv6);

			/* Crypt key size is fixed to 8 bytes. */
			server->crypt_key_length = 8;

			memcpy(server->crypt_key,SMB_BUF(packet),server->crypt_key_length);

			/* We translate this into capabilities. According to the
			 * LAN Manager 1.x/2.0 documentation both bits 0+1 being set
			 * means the same thing as CAP_RAW_MODE being set.
			 */
			if((blkmode & 3) == 3)
				server->capabilities = CAP_RAW_MODE;
		}

		SHOWVALUE(server->security_mode);

		if(server->security_mode & NEGOTIATE_ENCRYPT_PASSWORDS)
		{
			SHOWMSG("encrypted passwords required");

			/* Maximum password length for smb_encrypt() is 14 characters, which
			 * does not include the terminating NUL byte.
			 */
			smb_encrypt(server->mount_data.password,server->crypt_key,oem_password);
			oem_password_len = 24;

			/* Maximum password length for smb_nt_encrypt() is 128 characters, which
			 * does not include the terminating NUL byte.
			 */
			smb_nt_encrypt(server->mount_data.password,server->crypt_key,unicode_password);
			unicode_password_len = 24;
		}
		else
		{
			SHOWMSG("plain text passwords sufficient");

			/* Note: the password is an array of bytes, not a NUL-terminated string. */
			oem_password_len = strlen(server->mount_data.password);
			unicode_password_len = 0;
		}

		/* If in share level security then don't send a password just now, it will follow later. */
		if((server->security_mode & NEGOTIATE_USER_SECURITY) == 0)
		{
			SHOWMSG("share level security; not sending a password or user name just now");

			oem_password_len = 0;
			unicode_password_len = 0;
			user_len = 0;
		}
		else
		{
			SHOWMSG("user share level security");
		}

		SHOWVALUE(oem_password_len);
		SHOWVALUE(unicode_password_len);

		D(("workgroup = %s", server->mount_data.workgroup_name));

		/* NT LAN Manager or newer. */
		if (server->protocol >= PROTOCOL_NT1)
		{
			const char *native_os = "AmigaOS";
			const char *native_lanman = VERS;
			dword client_capabilities;
			int num_bytes;

			SHOWMSG("server->protocol >= PROTOCOL_NT1");

			client_capabilities = CAP_LARGE_READX|CAP_LARGE_WRITEX|CAP_NT_FIND|CAP_LARGE_FILES;

			if(server->use_unicode && (server->capabilities & CAP_UNICODE) != 0)
			{
				/* We may be able to use Unicode strings during the session setup,
				 * but the server may not understand it (Windows 7 seems to be
				 * unable to decode the strings), so we delay setting the SMB message
				 * flag "this message may contain Unicode strings" until we have
				 * completed the session setup.
				 */
				if(server->session_setup_delay_unicode)
				{
					SHOWMSG("Unicode support possible; delaying enabling it...");

					enable_unicode = TRUE;
				}
				else
				{
					SHOWMSG("Unicode support enabled");

					server->unicode_enabled = TRUE;
				}

				client_capabilities |= CAP_UNICODE;
			}
			else
			{
				SHOWMSG("Unicode support disabled");
			}

			if(server->unicode_enabled)
			{
				/* Use plain text passwords? Remember to transmit the
				 * password in UTF16LE-encoding. Note that we have to
				 * use the UTF16LE-encoded form, and not the OEM
				 * form.
				 */
				if((server->security_mode & NEGOTIATE_ENCRYPT_PASSWORDS) == 0)
				{
					SHOWMSG("plain text passwords will be sent; must be unicode-encoded.");

					unicode_password_len = 2 * oem_password_len;
					oem_password_len = 0;
				}

				ASSERT( smb_payload_size(server, 13, oem_password_len + unicode_password_len + 2 * (user_len+1) + 2 * (strlen (server->mount_data.workgroup_name)+1) + 2 * (strlen (native_os)+1) + 2 * (strlen (native_lanman)+1)) >= 0 );

				smb_setup_header (server, SMBsesssetupX, 13, oem_password_len + unicode_password_len + 2 * (user_len+1) + 2 * (strlen (server->mount_data.workgroup_name)+1) + 2 * (strlen (native_os)+1) + 2 * (strlen (native_lanman)+1));
			}
			else
			{
				ASSERT( smb_payload_size(server, 13, oem_password_len + unicode_password_len + user_len+1 + strlen (server->mount_data.workgroup_name)+1 + strlen (native_os)+1 + strlen (native_lanman)+1) >= 0 );

				smb_setup_header (server, SMBsesssetupX, 13, oem_password_len + unicode_password_len + user_len+1 + strlen (server->mount_data.workgroup_name)+1 + strlen (native_os)+1 + strlen (native_lanman)+1);
			}

			WSET (packet, smb_vwv0, 0xff);					/* AndXCommand+AndXReserved */
			WSET (packet, smb_vwv1, 0);						/* AndXOffset */
			WSET (packet, smb_vwv2, given_max_xmit);		/* MaxBufferSize */
			WSET (packet, smb_vwv3, 2);						/* MaxMpxCount */
			WSET (packet, smb_vwv4, 0);						/* VcNumber */
			DSET (packet, smb_vwv5, server_sesskey);		/* SessionKey */
			WSET (packet, smb_vwv7, oem_password_len);		/* OEMPasswordLen */
			WSET (packet, smb_vwv8, unicode_password_len);	/* UnicodePasswordLen */
			DSET (packet, smb_vwv9, 0);						/* Reserved */
			DSET (packet, smb_vwv11, client_capabilities);	/* Capabilities */

			p = SMB_BUF (packet);

			num_bytes = 0;

			/* Add the encrypted passwords now? */
			if(server->security_mode & NEGOTIATE_ENCRYPT_PASSWORDS)
			{
				SHOWMSG("adding encrypted passwords");

				memcpy (&p[num_bytes], oem_password, oem_password_len);
				num_bytes += oem_password_len;

				memcpy (&p[num_bytes], unicode_password, unicode_password_len);
				num_bytes += unicode_password_len;
			}
			/* No, just add the plain text password. */
			else
			{
				SHOWMSG("adding plain text password");

				/* Add either the Unicode password or the OEM password,
				 * but not both.
				 */
				if(server->unicode_enabled)
				{
					int i,j;

					/* Simplistic conversion to UTF16LE -- we do this here
					 * because the password must not be NUL-terminated, which
					 * copy_latin1_to_utf16le() would do.
					 */
					for(i = j = 0 ; i < unicode_password_len ; i += 2, j++)
					{
						p[num_bytes++] = server->mount_data.password[j];
						p[num_bytes++] = 0;
					}
				}
				else
				{
					memcpy (&p[num_bytes], server->mount_data.password, oem_password_len);
					num_bytes += oem_password_len;
				}
			}

			/* Add a padding byte to align the following Unicode
			 * strings, if necessary.
			 */
			if(server->unicode_enabled && (num_bytes % 2) == 0)
			{
				SHOWMSG("adding a padding byte");
				p[num_bytes++] = 0;
			}
			else
			{
				SHOWMSG("no padding byte necessary");
			}

			p += num_bytes;

			/* Add the user name, the workgroup name, etc. as Unicode strings? */
			if(server->unicode_enabled)
			{
				const char * s;
				int l;

				// TODO: Tygre
				copy_latin1_to_utf16le(server, p,2 * (user_len + 1),server->mount_data.username,user_len);
				p += 2 * (user_len + 1);

				s = server->mount_data.workgroup_name;
				l = strlen(s);
				copy_latin1_to_utf16le(server, p,2 * (l + 1),s,l);
				p += 2 * (l + 1);

				s = native_os;
				l = strlen(s);
				copy_latin1_to_utf16le(server, p,2 * (l + 1),s,l);
				p += 2 * (l + 1);

				s = native_lanman;
				l = strlen(s);
				copy_latin1_to_utf16le(server, p,2 * (l + 1),s,l);
			}
			/* No, just use OEM strings. */
			else
			{
				if(user_len == 0)
				{
					(*p++) = '\0';
				}
				else
				{
					memcpy (p, server->mount_data.username, user_len + 1);
					p += user_len + 1;
				}

				strcpy (p, server->mount_data.workgroup_name);
				p += strlen (p) + 1;

				strcpy (p, native_os);
				p += strlen (p) + 1;

				strcpy (p, native_lanman);
			}
		}
		/* LAN Manager 2.0 or older */
		else
		{
			ASSERT( smb_payload_size(server, 10, oem_password_len + user_len+1) >= 0 );

			smb_setup_header (server, SMBsesssetupX, 10, oem_password_len + user_len+1);

			WSET (packet, smb_vwv0, 0xff);	/* No further ANDX command */
			WSET (packet, smb_vwv1, 0);		/* ANDX offset = 0 */

			WSET (packet, smb_vwv2, given_max_xmit);	/* maximum buffer size */
			WSET (packet, smb_vwv3, 2);					/* maximum mpx count; should be copied from server */
			WSET (packet, smb_vwv4, 0); /* server->pid */
			DSET (packet, smb_vwv5, server_sesskey);
			WSET (packet, smb_vwv7, oem_password_len);	/* case sensitive password length */
			WSET (packet, smb_vwv8, 0);	/* no encrypted password */

			p = SMB_BUF (packet);

			/* Password text is not NUL-terminated. */
			memcpy (p, server->mount_data.password, oem_password_len);
			p += oem_password_len;

			/* User name must be NUL-terminated. */
			if(user_len > 0)
				memcpy (p, server->mount_data.username, user_len+1);
			else
				(*p) = 0;
		}

		result = smb_request_ok (server, SMBsesssetupX, 3, 0, error_ptr);
		if (result < 0)
		{
			SHOWMSG("SMBsessetupX fail");
			goto out;
		}

		smb_decode_word (packet + 32, &server->server_uid);
	}
	else
	{
		max_buffer_size = server->max_buffer_size;

		#if defined(OVERRIDE_SERVER_MAX_BUFFER_SIZE)
		{
			max_buffer_size = OVERRIDE_SERVER_MAX_BUFFER_SIZE;
		}
		#endif /* OVERRIDE_SERVER_MAX_BUFFER_SIZE */

		server->capabilities = 0;

		oem_password_len = 0;
	}

	if(server->protocol > PROTOCOL_LANMAN1 &&
	  (server->security_mode & (NEGOTIATE_USER_SECURITY|NEGOTIATE_ENCRYPT_PASSWORDS)) == (NEGOTIATE_USER_SECURITY|NEGOTIATE_ENCRYPT_PASSWORDS))
	{
		int server_name_len;
		int service_len;
		int share_name_len;
		int share_name_size;
		int padding_needed;

		SHOWMSG("protocol is LAN Manager 2.0 or better, user level access is enabled, encrypted passwords are used.");

		server_name_len = strlen(server->mount_data.server_name);
		service_len = strlen(server->mount_data.service);

		share_name_len = 2 + server_name_len + 1 + service_len;

		share_name = malloc(share_name_len+1);
		if(share_name == NULL)
		{
			SHOWMSG("No memory! Bailing out.");

			(*error_ptr) = ENOMEM;

			result = -1;
			goto out;
		}

		memcpy(share_name,"//",2);
		memcpy(&share_name[2],server->mount_data.server_name,server_name_len);
		share_name[2 + server_name_len] = '/';
		memcpy(&share_name[2 + server_name_len + 1],server->mount_data.service,service_len+1); /* Length includes terminating NUL byte. */

		/* Flip the slashes, so they become backslashes. */
		for(i = 0 ; i < share_name_len ; i++)
		{
			if(share_name[i] == '/')
				share_name[i] = '\\';
		}

		string_toupper(share_name);

		D(("share_name = '%s'", escape_name(share_name)));

		if(server->unicode_enabled)
			share_name_size = 2 * (share_name_len + 1);
		else
			share_name_size = share_name_len + 1;

		if(server->unicode_enabled && (oem_password_len % 2) == 0)
			padding_needed = 1;
		else
			padding_needed = 0;

		ASSERT( smb_payload_size(server, 4, oem_password_len + padding_needed + share_name_size + strlen(dev)+1) >= 0 );

		smb_setup_header (server, SMBtconX, 4, oem_password_len + padding_needed + share_name_size + strlen(dev)+1);

		WSET (packet, smb_vwv0, 0xFF);
		WSET (packet, smb_vwv3, oem_password_len);

		p = SMB_BUF (packet);

		memcpy(p,oem_password,oem_password_len);
		p += oem_password_len;

		if(padding_needed)
			(*p++) = 0;

		if(server->unicode_enabled)
		{
			copy_latin1_to_utf16le(server, p,share_name_size,share_name,share_name_len);
		}
		else
		{
			memcpy(p,share_name,share_name_size);
		}

		p += share_name_size;

		strcpy(p,dev);

		SHOWMSG("Using SMB_TREE_CONNECT_ANDX");

		result = smb_request_ok (server, SMBtconX, 3, 0, error_ptr);
		if (result < 0)
		{
			SHOWVALUE(SMB_WCT(packet));

			SHOWMSG("SMBtconX not verifie");
			goto out;
		}

		SHOWVALUE(SMB_WCT(packet));

		server->tid = WVAL(packet,smb_tid);
	}
	else
	{
		word decoded_max_xmit;

		SHOWMSG("Using SMB_TREE_CONNECT");

		ASSERT( NOT server->unicode_enabled );

		ASSERT( smb_payload_size(server, 0, 6 + strlen (server->mount_data.service) + strlen (server->mount_data.password) + strlen (dev)) >= 0 );

		/* Fine! We have a connection, send a tcon message. */
		smb_setup_header (server, SMBtcon, 0, 6 + strlen (server->mount_data.service) + strlen (server->mount_data.password) + strlen (dev));

		p = SMB_BUF (packet);
		p = smb_encode_ascii (p, server->mount_data.service, strlen (server->mount_data.service));
		p = smb_encode_ascii (p, server->mount_data.password, strlen (server->mount_data.password));
		(void) smb_encode_ascii (p, dev, strlen (dev));

		result = smb_request_ok (server, SMBtcon, 2, 0, error_ptr);
		if (result < 0)
		{
			SHOWMSG("SMBtcon not verified.");
			goto out;
		}

		SHOWMSG("OK! Managed to set up SMBtcon!");

		p = SMB_VWV (packet);
		p = smb_decode_word (p, &decoded_max_xmit);

		max_buffer_size = decoded_max_xmit;

		#if defined(OVERRIDE_SERVER_MAX_BUFFER_SIZE)
		{
			max_buffer_size = OVERRIDE_SERVER_MAX_BUFFER_SIZE;
		}
		#endif /* OVERRIDE_SERVER_MAX_BUFFER_SIZE */

		(void) smb_decode_word (p, &server->tid);
	}

	D(("max_buffer_size = %ld, tid = %ld", max_buffer_size, server->tid));

	/* Let's get paranoid. Make sure that we can actually receive
	 * as much data as the buffer size allows, in a single consecutive
	 * buffer which follows the SMB message header.
	 */
	if(packet_size < (int)max_buffer_size)
	{
		SHOWVALUE(packet_size);

		/* We need to allocate a larger packet buffer. */
		packet_size = max_buffer_size;

		D(("packet size updated to %ld bytes", packet_size));

		free (server->transmit_buffer);

		server->transmit_buffer_size = packet_size;

		/* Add a bit of fudge to account for the NetBIOS session
		 * header and whatever else might show up...
		 */
		server->transmit_buffer_allocation_size = server->transmit_buffer_size + safety_margin;

		server->transmit_buffer = malloc (server->transmit_buffer_allocation_size);
		if (server->transmit_buffer == NULL)
		{
			SHOWMSG("No memory! Bailing out.");

			(*error_ptr) = ENOMEM;

			result = -1;
			goto out;
		}
	}

	/* Finally, limit the amount of data to send to the server,
	 * if requested.
	 */
	if(8000 <= server->mount_data.given_max_xmit && server->mount_data.given_max_xmit < (int)max_buffer_size)
	{
		max_buffer_size = server->mount_data.given_max_xmit;
		D(("maximum buffer size limited to %ld bytes", max_buffer_size));
	}

	server->max_buffer_size = max_buffer_size;

	/* Now that the session has been set up properly,
	 * we may safely allow Unicode strings to be used
	 * in SMB messages.
	 */
	if(enable_unicode)
		server->unicode_enabled = TRUE;

	SHOWMSG("Normal exit");

	result = 0;

 out:

	if(share_name != NULL)
		free(share_name);

	if(result < 0)
		server->state = CONN_INVALID;

	return result;
}

/* smb_proc_reconnect: server->transmit_buffer is allocated with
 * server->max_buffer_size bytes if and only if we return >= 0
 */
int
smb_proc_connect (struct smb_server *server, int * error_ptr)
{
	int result;

	result = smb_proc_reconnect (server, error_ptr);

	if ((result < 0) && (server->transmit_buffer != NULL))
	{
		free (server->transmit_buffer);
		server->transmit_buffer = NULL;
	}

	return result;
}

static void
smb_printerr (int class, int num)
{
	const err_code_struct *err;
	int i, j;

	for (i = 0; err_classes[i].class; i++)
	{
		if (err_classes[i].code != class)
			continue;

		if (!err_classes[i].err_msgs)
		{
			report_error("%s - %ld.", err_classes[i].class, num);

			D(("%s - %ld", err_classes[i].class, num));
			return;
		}

		err = (err_code_struct *)err_classes[i].err_msgs;

		for (j = 0; err[j].name; j++)
		{
			if (num != err[j].code)
				continue;

			report_error ("%s - %s (%s).", err_classes[i].class, err[j].name, err[j].message);

			D(("%s - %s (%s)", err_classes[i].class, err[j].name, err[j].message));
			return;
		}
	}

	report_error ("Unknown error - (%ld, %ld).", class, num);

	D(("Unknown error - (%ld, %ld)", class, num));
}
