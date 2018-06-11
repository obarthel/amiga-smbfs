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
#define SMB_STATUS_SIZE		21

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
   merik -at- blackadder -dot- dsh -dot- oz -dot- au */
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

/* Copy a string in ISO-Latin-1 form (8 bits per character) into a
 * buffer, converting it into a little-endian 16 bit Unicode version
 * of the string. This works because the ISO-Latin-1 sits within
 * the ASCII/BMP Latin-1 Unicode range.
 *
 * This function creates a null-terminated UTF16-LE Unicode string and
 * returns how many bytes were written to the buffer, including the
 * null-termination.
 */
static int
copy_latin1_to_utf16le(byte * to,int to_size, const byte * from,int len)
{
	int num_bytes_written = 0;
	int i;

	if(to_size >= 2)
	{
		to_size -= 2;

		for(i = 0 ; i < len ; i++)
		{
			if(num_bytes_written + 2 <= to_size)
			{
				(*to++) = (*from++);
				(*to++) = '\0';

				num_bytes_written += 2;
			}
		}

		(*to++) = '\0';
		(*to) = '\0';

		num_bytes_written += 2;
	}

	return(num_bytes_written);
}

/*****************************************************************************/

/* Copy a string in little-endian 16 bit Unicode into a buffer, converting
 * it into a ISO-Latin-1 (8 bits per character) version of the string, if
 * possible. Code points beyond the ASCII/BMP Latin-1 are replaced by the
 * control character 0x80.
 *
 * Note that the length is given as the number of 16 bit Unicode
 * characters, not the number of bytes required to store the string.
 *
 * This function creates a null-terminated ISO-Latin-1 string and
 * returns how many bytes were written to the buffer, including the
 * null-termination.
 */
static int
copy_utf16le_to_latin1(byte * to,int to_size,const byte * from,int len)
{
	int num_bytes_written = 0;
	word c;
	int i;

	if(to_size >= 1)
	{
		to_size -= 1;

		for(i = 0 ; i < len ; i++, from += 2)
		{
			c = ((word)from[1] << 8) | from[0];

			if(c >= 256)
				c = 0x80;

			if(num_bytes_written + 1 <= to_size)
			{
				(*to++) = c;
				num_bytes_written++;
			}
		}

		(*to) = '\0';

		num_bytes_written++;
	}

	return(num_bytes_written);
}

/*****************************************************************************/

/* Works just like strlen(), but stops as soon as it hits
 * the boundaries of the buffer which contains the string.
 */
static size_t strnlen(const char * s,size_t max_size)
{
	const char * start = s;
	size_t result;

	if(max_size > 0)
	{
		while((*s) != '\0' && --max_size > 0)
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

byte *
smb_encode_smb_length (byte * p, int len)
{
	/* 0x00 = NetBIOS session message */
	p[0] = 0;

	/* 0 = reserved */
	p[1] = 0;

	/* Payload length in network byte order. */
	p[2] = (len & 0xFF00) >> 8;
	p[3] = (len & 0xFF);

	/* Length is actually a 17 bit integer. */
	p[1] |= (len >> 16) & 1;

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
	(*p++) = 4;

	memcpy (p, name, len);
	p[len] = '\0';

	return p + len + 1;
}

static void
smb_encode_vblock (byte * p, const byte * data, int len)
{
	ASSERT( 0 <= len && len <= 65535 );

	(*p++) = 5;
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
	struct tm tm;

	memset(&tm,0,sizeof(tm));

	tm.tm_sec = 2 * (time_value & 0x1F);
	tm.tm_min = (time_value >> 5) & 0x3F;
	tm.tm_hour = (time_value >> 11) & 0x1F;
	tm.tm_mday = date & 0x1F;
	tm.tm_mon = ((date >> 5) & 0xF) - 1;
	tm.tm_year = ((date >> 9) & 0x7F) + 80;

	seconds = tm_to_seconds(&tm);

	return(seconds);
}

/* Convert linear UNIX date to a MS-DOS time/date pair. */
static void
date_unix2dos (int unix_date, unsigned short *time_value, unsigned short *date)
{
	struct tm tm;

	seconds_to_tm(unix_date,&tm);

	(*time_value) = (tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2);
	(*date) = ((tm.tm_year - 80) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday;
}

/****************************************************************************
 *
 *  Support section.
 *
 ****************************************************************************/
int
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
   requirements of a smb packet */
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
   got enough data. If bcc == -1, we don't care. */
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
			{ 145,				ENOTEMPTY},/* Directory is not empty; this is what Samba reports (2016-04-23) */
			{ 183,				EEXIST },/* This next error seems to occur on an mv when the destination exists ("object name collision") */
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
			LOG(("translated error code %ld/%ld (%s/%s) to %ld (%s)\n",
				errcls,error,err_class->class,err_code->message,result,strerror(result)));
		}
		else
		{
			LOG(("no proper translation for error code %ld/%ld to %ld (%s)\n",
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

	LOG (("smb_len = %ld valid = %ld\n", len = smb_len (packet), smb_valid_packet (packet)));
	LOG (("smb_cmd = %ld smb_wct = %ld smb_bcc = %ld\n", packet[8], SMB_WCT (packet), SMB_BCC (packet)));
	LOG (("smb_rcls = %ld smb_err = %ld\n", errcls, error));

	if (errcls)
		smb_printerr (errcls, error);

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

/* smb_request_ok: We expect the server to be locked. Then we do the
   request and check the answer completely. When smb_request_ok
   returns 0, you can be quite sure that everything went well. When
   the answer is <=0, the returned number is a valid unix errno. */
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
		LOG (("smb_request failed\n"));
	}
	/* The message received is inconsistent? */
	else if ((error = smb_valid_packet (server->transmit_buffer)) != 0)
	{
		LOG (("not a valid packet!\n"));

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
		LOG (("smb_verify failed\n"));

		(*error_ptr) = error;
		result = -1;
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

		LOG (("trying to reopen file '%s'\n", escape_name(entry->complete_path)));

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
		LOG (("smb_proc_reconnect failed\n"));

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
		LOG (("Danger: total packet size (%ld) > transmit buffer allocation (%ld)!\n", smb_frame_size, server->transmit_buffer_allocation_size));

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
		BSET (buf, smb_flg, SMB_FLG_CASELESS_PATHNAMES);
		WSET (buf, smb_flg2, SMB_FLG2_KNOWS_LONG_NAMES|SMB_FLG2_EAS|(server->unicode_enabled ? SMB_FLG2_UNICODE_STRINGS : 0));
	}

	(*p++) = wct;
	p += wct * sizeof(word);

	WSET (p, 0, bcc);

	LOG (("total packet size=%ld, max receive size=%ld, packet buffer size=%ld\n",
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
smb_proc_open (struct smb_server *server, const char *pathname, int len, int writable, int truncate_file, struct smb_dirent *entry,int * error_ptr)
{
	int result;
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
			pathname_size = 2 * (len + 1);
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
				/* desired_access = FILE_READ_DATA|FILE_WRITE_DATA|FILE_DELETE; */

				desired_access = GENERIC_READ|GENERIC_WRITE;
			}
			else
			{
				SHOWMSG("read access is sufficient");

				/* The following does not work consistently with multiple
				 * SMB servers. Which is why we stick with generic read.
				 */
				/* desired_access = FILE_READ_DATA; */

				desired_access = GENERIC_READ;
			}

			/* desired_access |= FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES; */

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
				(*data++) = 0;

				copy_latin1_to_utf16le(data, pathname_size, pathname, len);
			}
			else
			{
				(void) smb_copy_data(data, pathname, pathname_size); /* Length includes the terminating NUL byte. */
			}

			LOG(("requesting SMBntcreateX\n"));

			result = smb_request_ok(server, SMBntcreateX, 34, 0, error_ptr);
			if (result < 0)
			{
				SHOWMSG("that didn't work; retrying");

				/* Try again in read-only mode? */
				if ((*error_ptr) == EACCES || ((*error_ptr) == error_check_smb_error && smb_errno(server->rcls,server->err) == EACCES))
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

				if (smb_retry (server))
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

		entry->opened = TRUE;
		entry->writable = writable;
	}
	else
	{
		word access_and_share_modes;
		int path_size;

		if(server->unicode_enabled)
			path_size = 1 + 2 * (len+1);
		else
			path_size = 1 + len+1;

		ASSERT( smb_payload_size(server, 2, path_size) >= 0 );

		SHOWMSG("using the old SMB_COM_OPEN");

		while(TRUE)
		{
			if(writable)
				access_and_share_modes = SMB_OPEN_SHARE_DENY_NOTHING|SMB_OPEN_ACCESS_READ_WRITE;
			else
				access_and_share_modes = SMB_OPEN_SHARE_DENY_NOTHING|SMB_OPEN_ACCESS_READ_ONLY;

			p = smb_setup_header (server, SMBopen, 2, path_size);
			WSET (buf, smb_vwv0, access_and_share_modes);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_HIDDEN|SMB_FILE_ATTRIBUTE_SYSTEM|SMB_FILE_ATTRIBUTE_DIRECTORY);

			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A null-terminated string follows. */
				copy_latin1_to_utf16le(p,2 * (len+1),pathname,len);
			}
			else
			{
				smb_encode_ascii (p, pathname, len);
			}

			result = smb_request_ok (server, SMBopen, 7, 0, error_ptr);
			if (result < 0)
			{
				/* Try again in read-only mode? */
				if ((*error_ptr) == EACCES || ((*error_ptr) == error_check_smb_error && smb_errno(server->rcls,server->err) == EACCES))
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

				if (smb_retry (server))
					continue;
				else
					goto out;
			}

			break;
		}

		/* We should now have data in vwv[0..6]. */
		entry->fileid = WVAL (buf, smb_vwv0);

		entry->attr = WVAL (buf, smb_vwv1);

		/* This is actually just the mtime value, but we use it
		 * in all other places as well.
		 */
		entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc (DVAL (buf, smb_vwv2));

		entry->size_low = DVAL (buf, smb_vwv4);
		entry->size_high = 0;

		entry->opened = TRUE;
		entry->writable = writable;
	}

 out:

	RETURN(result);
	return(result);
}

/* smb_proc_close: in finfo->mtime we can send a modification time to
   the server */
int
smb_proc_close (struct smb_server *server, word fileid, dword mtime, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	/* 0 and 0xffffffff mean: do not set mtime */
	if(mtime != 0 && mtime != (dword)0xffffffff)
		mtime = utc2local (mtime);

	smb_setup_header (server, SMBclose, 3, 0);
	WSET (buf, smb_vwv0, fileid);
	DSET (buf, smb_vwv1, mtime);

	result = smb_request_ok (server, SMBclose, 0, 0, error_ptr);

	return result;
}

/* In smb_proc_read and smb_proc_write we do not retry, because the
   file-id would not be valid after a reconnection. */

int
smb_proc_read (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, char *data, int * error_ptr)
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

	LOG(("requesting %ld bytes\n", count));

	result = smb_request_ok_with_payload (server, SMBread, 5, -1, data, NULL, count, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) < 0)
			{
				LOG(("that didn't work.\n"));
				goto out;
			}
			else
			{
				goto retry;
			}
		}
		else
		{
			goto out;
		}
	}

	/* The buffer format must be 1; smb_request_ok_with_payload() already checked this. */
	LOG(("buffer_format=%ld, should be %ld\n", BVAL(buf, NETBIOS_HEADER_SIZE+45), 1));

	result = WVAL (buf, NETBIOS_HEADER_SIZE+46); /* count of bytes to read */

	ASSERT( result <= count );

	LOG(("read %ld bytes (should be < %ld)\n", result, count));

 out:

	return result;
}

/* count must be <= 65535. No error number is returned. A result of 0
   indicates an error, which has to be investigated by a normal read
   call. */
int
smb_proc_read_raw (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset_quad, long count, char *data, int * error_ptr)
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
		if (smb_retry (server))
			goto retry;
	}

	return result;
}

int
smb_proc_write (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, const char *data, int * error_ptr)
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
		if (smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) < 0)
				LOG(("that didn't work.\n"));
			else
				goto retry;
		}
	}
	else
	{
		result = WVAL (buf, smb_vwv0);
	}

	return result;
}

int
smb_proc_write_raw (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset_quad, long count, const char *data, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int num_bytes_written = 0;
	int result;
	long max_len;
	long len;
	byte *p;

	ASSERT( count <= 65535 );

	LOG (("number of bytes to send = %ld\n", count));

	/* Calculate maximum number of bytes that could be transferred with
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

	LOG(("maximum length for payload = %ld bytes\n", max_len));

	/* Number of bytes to write is smaller than the maximum
	 * number of bytes which may be sent in a single SMB
	 * message, including parameter and data fields?
	 */
	if (count <= max_len)
	{
		LOG(("count (%ld) <= max_len (%ld) -- send no data with the message.\n",count,max_len));

		len = 0; /* Send a zero length SMB_COM_WRITE_RAW message, followed by the raw data. */
	}
	else
	{
		len = count - max_len; /* Send some of the data as part of the SMB_COM_WRITE_RAW message, followed by the remaining raw data. */

		LOG(("count (%ld) > max_len (%ld) -- send %ld bytes with the message.\n",count,max_len,len));
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

	if (server->protocol > PROTOCOL_COREPLUS)
	{
		WSET (buf, smb_vwv10, len);
		WSET (buf, smb_vwv11, p - smb_base(buf));
		WSET (buf, smb_vwv12, offset_quad->High);
	}
	else
	{
		WSET (buf, smb_vwv10, 0);
	}

	LOG(("requesting SMBwritebraw\n"));

	result = smb_request_ok_with_payload (server, SMBwritebraw, 1, 0, NULL, data, len, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
			goto retry;
		else
			goto out;
	}

	num_bytes_written += len;

	data += len;
	count -= len;

	LOG (("bytes sent so far = %ld\n", num_bytes_written));

	if(count > 0)
	{
		LOG(("sending %ld bytes of data (raw)\n",count));

		ASSERT( count <= 65535 );

		result = smb_request_write_raw (server, data, count, error_ptr);
		if (result < 0)
		{
			/* Roll back the counters */
			num_bytes_written -= len;

			data -= len;
			count += len;

			if (smb_retry (server))
				goto retry;
			else
				goto out;
		}

		if(server->write_behind)
		{
			/* We just assume success; the next file operation to follow
			 * will set an error status if something went wrong.
			 */
			result = num_bytes_written + count;
		}
		else
		{
			int error;

			/* We have to do the checks of smb_request_ok here as well */
			if ((error = smb_valid_packet (server->transmit_buffer)) != 0)
			{
				LOG (("not a valid packet!\n"));

				(*error_ptr) = error;
				result = -1;

				goto out;
			}
			else if (server->rcls != 0)
			{
				LOG (("server error %ld/%ld\n", server->rcls, server->err));

				smb_printerr (server->rcls, server->err);

				(*error_ptr) = error_check_smb_error;
				result = -1;

				goto out;
			}

			result = num_bytes_written + count;
		}

		LOG (("bytes sent so far = %ld\n", result));
	}

 out:

	return result;
}

int
smb_proc_writex (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset_quad, long count, const char *data, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;
	byte *p;

	ASSERT( count <= 65535 );

	LOG (("number of bytes to send = %ld\n", count));

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


	LOG(("requesting SMBwriteX: offset=%s, count=%ld\n", convert_quad_to_string(offset_quad), count));

	result = smb_request_ok_with_payload (server, SMBwriteX, 6, 0, NULL, data, count, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) < 0)
				LOG(("that didn't work.\n"));
			else
				goto retry;
		}
	}
	else
	{
		word available;

		p = SMB_VWV (server->transmit_buffer);
		smb_decode_word (p + 4, &available);

		LOG(("number of bytes written = %ld\n", available));

		result = available;
	}

	return result;
}

int
smb_proc_readx (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset_quad, long count, char *data, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;
	byte *p;

	ASSERT( count <= 65535 );

	LOG (("number of bytes to read = %ld\n", count));

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

	LOG(("requesting SMBreadX: offset=%s, count=%ld\n", convert_quad_to_string(offset_quad), count));

	result = smb_request_ok_with_payload (server, SMBreadX, 7, 0, data, NULL, count, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) < 0)
				LOG(("that didn't work.\n"));
			else
				goto retry;
		}
	}
	else
	{
		word data_length;

		p = SMB_VWV (server->transmit_buffer);
		smb_decode_word (p + 10, &data_length);

		LOG(("number of bytes read = %ld\n", data_length));

		result = data_length;
	}

	return result;
}

/* smb_proc_lockingX: We don't chain any further packets to the initial one */
int
smb_proc_lockingX (struct smb_server *server, struct smb_dirent *finfo, const struct smb_lkrng *locks, int num_entries, int mode, long timeout, int * error_ptr)
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
		if (smb_retry (server))
		{
			if(reopen_entry(server,finfo,NULL) < 0)
				LOG(("that didn't work.\n"));
			else
				goto retry;
		}
	}

	return result;
}

/* smb_proc_do_create: We expect entry->attry & entry->ctime to be set. */
int
smb_proc_create (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr)
{
	dword local_time = utc2local (entry->ctime);
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	int path_size;

	if(server->unicode_enabled)
		path_size = 1 + 2 * (len + 1);
	else
		path_size = 1 + len + 1;

 retry:

	ASSERT( smb_payload_size(server, 3, path_size) >= 0 );

	p = smb_setup_header (server, SMBcreate, 3, path_size);
	WSET (buf, smb_vwv0, entry->attr);
	DSET (buf, smb_vwv1, local_time);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A null-terminated string follows. */
		copy_latin1_to_utf16le(p,2 * (len+1),path,len);
	}
	else
	{
		smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBcreate, 1, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
			goto retry;
		else
			goto out;
	}

	entry->opened = TRUE;
	entry->fileid = WVAL (buf, smb_vwv0);

	/* Don't change the modification time. */
	smb_proc_close (server, entry->fileid, 0, error_ptr);

 out:

	return result;
}

int
smb_proc_mv (struct smb_server *server, const char *old_path, const int old_path_len, const char *new_path, const int new_path_len, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int size;
	int result;

	if(server->unicode_enabled)
		size = 2 + 1 + 2 * (old_path_len+1) + 1 + 2 * (new_path_len+1);
	else
		size = 2 + 1 + (old_path_len+1) + 1 + (new_path_len+1);

	ASSERT( smb_payload_size(server, 1, size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBmv, 1, size);

	WSET (buf, smb_vwv0, SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_HIDDEN);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A null-terminated string follows. */
		p += copy_latin1_to_utf16le(p,2 * (old_path_len+1),old_path,old_path_len);

		(*p++) = 4; /* A null-terminated string follows. */
		(void) copy_latin1_to_utf16le(p,2 * (new_path_len+1),new_path,new_path_len);
	}
	else
	{
		p = smb_encode_ascii (p, old_path, old_path_len);
		(void) smb_encode_ascii (p, new_path, new_path_len);
	}

	result = smb_request_ok (server, SMBmv, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
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

	if(server->unicode_enabled)
		path_size = 2 * (len + 1);
	else
		path_size = len + 1;

 retry:

	/* olsen (2018-05-20): The TRANSACT2_MKDIR command does not seem to
	 *                     work correctly with Samba 3.0.25, although the
	 *                     implementation appears to be sound (it follows
	 *                     both the SNIA and Microsoft CIFS documentation,
	 *                     as well as the 1996 Microsoft SMB file sharing
	 *                     protocol documentation). The extended attributes
	 *                     are documented as being optional, and we omit
	 *                     them here.
	 */
	if (FALSE && server->protocol >= PROTOCOL_LANMAN2)
	{
		unsigned char *outbuf = server->transmit_buffer;

		ASSERT( smb_payload_size(server, 15, 3 + 4 + path_size) >= 0 );

		smb_setup_header (server, SMBtrans2, 15, 3 + 4 + path_size);

		WSET (outbuf, smb_tpscnt, 4 + path_size);							/* TotalParameterCount */
		WSET (outbuf, smb_tdscnt, 0);										/* TotalDataCount */
		WSET (outbuf, smb_mprcnt, 2);										/* MaxParameterCount */
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
		WSET (outbuf, smb_setup0, TRANSACT2_MKDIR);							/* Setup[0] */

		p = SMB_BUF (outbuf);

		/* Align to a 4-byte-boundary. */
		(*p++) = '\0';
		(*p++) = '\0';
		(*p++) = '\0';

		DSET (p, 0, 0);	/* Reserved */
		p += 4;

		if(server->unicode_enabled)
		{
			copy_latin1_to_utf16le(p,path_size,path,len);
		}
		else
		{
			memcpy(p,path,len);
			p[len] = '\0';
		}

		result = smb_trans2_request (server, SMBtrans2, NULL, NULL, NULL, NULL, error_ptr);
		if (result < 0)
		{
			if((*error_ptr) != error_check_smb_error)
			{
				if (smb_retry (server))
					goto retry;
			}

			goto out;
		}

		if(server->rcls != 0)
		{
			(*error_ptr) = error_check_smb_error;

			result = -1;
			goto out;
		}
	}
	else
	{
		ASSERT( smb_payload_size(server, 0, 1 + path_size) >= 0 );

		p = smb_setup_header (server, SMBmkdir, 0, 1 + path_size);

		if(server->unicode_enabled)
		{
			(*p++) = 4; /* A null-terminated string follows. */
			(void) copy_latin1_to_utf16le(p,path_size,path,len);
		}
		else
		{
			(void) smb_encode_ascii (p, path, len);
		}

		result = smb_request_ok (server, SMBmkdir, 0, 0, error_ptr);
		if (result < 0)
		{
			if (smb_retry (server))
				goto retry;
		}
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

	if(server->unicode_enabled)
		path_size = 2 * (len + 1);
	else
		path_size = len + 1;

	ASSERT( smb_payload_size(server, 0, 1 + path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBrmdir, 0, 1 + path_size);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A null-terminated string follows. */
		(void) copy_latin1_to_utf16le(p,path_size,path,len);
	}
	else
	{
		(void) smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBrmdir, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
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
		(*p++) = 4; /* A null-terminated string follows. */
		(void) copy_latin1_to_utf16le(p,path_size,path,len);
	}
	else
	{
		(void) smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBunlink, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
			goto retry;
	}

	return result;
}

int
smb_proc_trunc (struct smb_server *server, word fid, dword length, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int result;

	ASSERT( smb_payload_size(server, 5, 3) >= 0 );

 retry:

	p = smb_setup_header (server, SMBwrite, 5, 3);
	WSET (buf, smb_vwv0, fid);
	WSET (buf, smb_vwv1, 0);
	DSET (buf, smb_vwv2, length);
	WSET (buf, smb_vwv4, 0);

	smb_encode_ascii (p, "", 0);

	result = smb_request_ok (server, SMBwrite, 1, 0, error_ptr);
	if(result < 0)
	{
		if (smb_retry (server))
			goto retry;
	}
	else
	{
		result = DVAL(buf, smb_vwv0);
	}

	return result;
}

static int
smb_decode_dirent (const char *p, struct smb_dirent *entry)
{
	size_t name_size;

	p += SMB_STATUS_SIZE; /* reserved (search_status) */

	entry->attr = BVAL (p, 0);
	entry->mtime = entry->atime = entry->ctime = entry->wtime = date_dos2unix (WVAL (p, 1), WVAL (p, 3));
	entry->size_low = DVAL (p, 5);
	entry->size_high = 0;

	name_size = 13;

	if(name_size > entry->complete_path_size-1)
		return(-1);

	memcpy (entry->complete_path, p + 9, name_size);

	entry->complete_path[name_size] = '\0';

	LOG (("path = '%s'\n", escape_name(entry->complete_path)));

	#if DEBUG
	{
		struct tm tm;

		seconds_to_tm(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

	return(0);
}

/* This routine is used to read in directory entries from the network.
   Note that it is for short directory name seeks, i.e.: protocol < PROTOCOL_LANMAN2 */
static int
smb_proc_readdir_short (struct smb_server *server, const char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
{
	char *p;
	char *buf;
	int result;
	int i;
	int first, total_count;
	struct smb_dirent *current_entry;
	word bcc;
	word count;
	char status[SMB_STATUS_SIZE];
	int entries_asked = (server->max_recv - 100) / SMB_DIRINFO_SIZE;
	int path_len = strlen (path);
	int mask_len;
	int mask_size;
	char * mask;

	mask = malloc(path_len + 4 + 1);
	if (mask == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memcpy(mask, path, path_len);
	memcpy(&mask[path_len], "\\*.*", 5); /* Length includes terminating NUL. */

	mask_len = strlen (mask);

	if(server->unicode_enabled)
		mask_size = 1 + 2 * (mask_len+1) + 3;
	else
		mask_size = 1 + mask_len+1 + 3;

	LOG (("SMB call readdir %ld @ %ld\n", cache_size, fpos));
	LOG (("                 mask = '%s'\n", escape_name(mask)));

	buf = server->transmit_buffer;

 retry:

	first = TRUE;
	total_count = 0;
	current_entry = entry;

	while (TRUE)
	{
		if (first)
		{
			ASSERT( smb_payload_size(server, 2, mask_size) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, mask_size);
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_DIRECTORY);

			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A null-terminated string follows. */
				p += copy_latin1_to_utf16le(p,2 * (mask_len+1),mask,mask_len);
			}
			else
			{
				p = smb_encode_ascii (p, mask, strlen (mask));
			}

			(*p++) = 5;
			(void) smb_encode_word (p, 0);
		}
		else
		{
			int size;

			if(server->unicode_enabled)
				size = 1 + 2 * (1) + 3 + SMB_STATUS_SIZE;
			else
				size = 1 + 1 + 3 + SMB_STATUS_SIZE;

			ASSERT( smb_payload_size(server, 2, size) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, size);
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, SMB_FILE_ATTRIBUTE_DIRECTORY);

			if(server->unicode_enabled)
			{
				(*p++) = 4; /* A null-terminated string follows. */
				p += copy_latin1_to_utf16le(p,2 * (1),"",0);
			}
			else
			{
				p = smb_encode_ascii (p, "", 0);
			}

			(void) smb_encode_vblock (p, status, SMB_STATUS_SIZE);
		}

		if (smb_request_ok (server, SMBsearch, 1, -1, error_ptr) < 0)
		{
			if (server->rcls == ERRDOS && server->err == ERRnofiles)
			{
				result = total_count - fpos;
				goto out;
			}
			else
			{
				if (smb_retry (server))
					goto retry;

				result = -1;
				goto out;
			}
		}

		p = SMB_VWV (server->transmit_buffer);
		p = smb_decode_word (p, &count); /* vwv[0] = count-returned */
		p = smb_decode_word (p, &bcc);

		first = FALSE;

		if (count <= 0)
		{
			result = total_count - fpos;

			goto out;
		}

		if (bcc != count * SMB_DIRINFO_SIZE + 3)
		{
			LOG (("byte count (%ld) does not match expected size (%ld)\n", bcc, count * SMB_DIRINFO_SIZE + 3));

			(*error_ptr) = error_invalid_directory_size;

			result = -1;
			goto out;
		}

		p += 3; /* Skipping VBLOCK header (5, length lo, length hi). */

		/* Read the last entry into the status field. */
		memcpy (status, SMB_BUF (server->transmit_buffer) + 3 + (count - 1) * SMB_DIRINFO_SIZE, SMB_STATUS_SIZE);

		/* Now we are ready to parse smb directory entries. */

		for (i = 0; i < count; i++)
		{
			if (total_count < fpos)
			{
				p += SMB_DIRINFO_SIZE;

				LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n", total_count, i, fpos));
			}
			else if (total_count >= fpos + cache_size)
			{
				result = total_count - fpos;

				goto out;
			}
			else
			{
				if(smb_decode_dirent (p, current_entry) == 0)
				{
					current_entry += 1;
				}
				else
				{
					p += SMB_DIRINFO_SIZE;

					LOG (("skipped entry because name is too long; total_count = %ld, i = %ld, fpos = %ld\n", total_count, i, fpos));
				}
			}

			total_count += 1;
		}
	}

 out:

	if(mask != NULL)
		free(mask);

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

static void
smb_get_dirent_name(char *p,int level,char ** name_ptr,int * len_ptr)
{
	switch (level)
	{
		case SMB_INFO_STANDARD:

			(*len_ptr) = p[26];
			(*name_ptr) = &p[27];
			break;

		case SMB_FILE_BOTH_DIRECTORY_INFO:

			(*len_ptr) = DVAL (p, 60);
			(*name_ptr) = &p[94];
			break;

		default:

			(*name_ptr) = NULL;
			(*len_ptr) = 0;
			break;
	}
}

/* interpret a long filename structure */
static int
smb_decode_long_dirent (const struct smb_server *server, const char *p, struct smb_dirent *finfo, int level, int * entry_length_ptr)
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
					D(("name length >= %ld (skipping it)", finfo->complete_path_size));

					success = FALSE;
					break;
				}

				if(name_len == 0)
				{
					D(("name length == 0 (skipping it)"));

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
					copy_utf16le_to_latin1(finfo->complete_path, finfo->complete_path_size, name, name_len);
				}
				else
				{
					memcpy(finfo->complete_path, name, name_len);
					finfo->complete_path[name_len] = '\0';
				}

				finfo->len = name_len;

				D(("name = '%s', length=%ld",escape_name(finfo->complete_path),name_len));
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
					D(("name length >= %ld (skipping it)", finfo->complete_path_size));

					success = FALSE;
					break;
				}

				if(name_len == 0)
				{
					D(("name length == 0 (skipping it)"));

					success = FALSE;
					break;
				}

				if(server->unicode_enabled)
				{
					copy_utf16le_to_latin1(finfo->complete_path, finfo->complete_path_size, p, name_len);
				}
				else
				{
					memcpy(finfo->complete_path, p, name_len);
					finfo->complete_path[name_len] = '\0';
				}

				finfo->len = name_len;

				D(("name = '%s', length=%ld",escape_name(finfo->complete_path),name_len));
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
smb_proc_readdir_long (struct smb_server *server, const char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
{
	int max_matches = 512; /* this should actually be based on the max_recv value */

	int info_level = server->protocol < PROTOCOL_NT1 ? SMB_INFO_STANDARD : SMB_FILE_BOTH_DIRECTORY_INFO;

	char *p;
	int i;
	int is_first;
	int total_count = 0;
	struct smb_dirent *current_entry;

	char *resp_data = NULL;
	char *resp_param = NULL;
	int resp_data_len = 0;
	int resp_param_len = 0;

	int attribute = SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_DIRECTORY;
	int result = 0;

	int ff_searchcount;
	int ff_end_of_search = 0;
	int ff_dir_handle = 0;
	int ff_resume_key = 0;
	int loop_count = 0;

	unsigned char *outbuf = server->transmit_buffer;

	int path_len = strlen(path);
	int mask_buffer_size = path_len + 2 + 1;
	char *mask;
	int mask_len;
	int mask_size;

	int entry_length;

	ENTER();

	/* ZZZ experimental 'max_matches' adjustment */
	/*
	if(info_level == SMB_FILE_BOTH_DIRECTORY_INFO)
		max_matches = server->max_recv / 360;
	else
		max_matches = server->max_recv / 40;
	*/

	SHOWVALUE(server->max_recv);
	SHOWVALUE(max_matches);

	mask = malloc (mask_buffer_size);
	if (mask == NULL)
	{
		LOG (("Memory allocation failed\n"));

		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memcpy(mask,path,path_len);
	memcpy(&mask[path_len],"\\*",3); /* This includes the terminating NUL. */

	mask_len = path_len + 2;

	LOG (("SMB call lreaddir %ld @ %ld\n", cache_size, fpos));
	LOG (("                  mask = '%s'\n", escape_name(mask)));

	resp_param = NULL;
	resp_data = NULL;

 retry:

	is_first = TRUE;
	total_count = 0;
	current_entry = entry;

	while (ff_end_of_search == 0)
	{
		loop_count++;
		if (loop_count > 200)
		{
			LOG (("Looping in FIND_NEXT???\n"));

			(*error_ptr) = error_looping_in_find_next;

			result = -1;
			break;
		}

		memset (outbuf, 0, sizeof(word) * smb_setup1);

		if(server->unicode_enabled)
			mask_size = 2 * (mask_len + 1);
		else
			mask_size = mask_len + 1;

		ASSERT( smb_payload_size(server, 15, 3 + 12 + mask_size) >= 0 );

		smb_setup_header (server, SMBtrans2, 15, 3 + 12 + mask_size);

		WSET (outbuf, smb_tpscnt, 12 + mask_size);							/* TotalParameterCount */
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

		if (is_first)
		{
			LOG (("first match\n"));
			WSET (p, 0, attribute); /* attribute */
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, SMB_FIND_CLOSE_AT_EOS|SMB_FIND_RETURN_RESUME_KEYS|SMB_FIND_CONTINUE_FROM_LAST);
			WSET (p, 6, info_level);
			DSET (p, 8, 0); /* return every entry there is */
		}
		else
		{
			LOG (("next match; ff_dir_handle=0x%lx ff_resume_key=%ld mask='%s'\n", ff_dir_handle, ff_resume_key, escape_name(mask)));
			WSET (p, 0, ff_dir_handle);
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, info_level);
			DSET (p, 6, ff_resume_key);
			WSET (p, 10, SMB_FIND_CLOSE_AT_EOS|SMB_FIND_RETURN_RESUME_KEYS|SMB_FIND_CONTINUE_FROM_LAST);
		}

		p += 12;

		if(server->unicode_enabled)
		{
			copy_latin1_to_utf16le(p,mask_size,mask,mask_len);
		}
		else
		{
			memcpy (p, mask, mask_len);
			p[mask_len] = '\0';
		}

		result = smb_trans2_request (server, SMBtrans2, &resp_data_len, &resp_param_len, &resp_data, &resp_param, error_ptr);

		LOG (("smb_trans2_request returns %ld\n", result));

		/* If an error was flagged, check is_first if it's a protocol
		 * error which could handle below. Otherwise, try again.
		 */
		if (result < 0 && (*error_ptr) != error_check_smb_error)
		{
			if (smb_retry (server))
				goto retry;

			LOG (("got error from trans2_request\n"));
			break;
		}

		/* Apparently, there is a bug in Windows 95 and friends which
		 * causes the directory read attempt to fail if you're asking
		 * for too much data too fast...
		 */
		if(server->rcls == ERRSRV && server->err == ERRerror)
		{
			SHOWMSG("ouch; delaying and retrying");

			Delay(TICKS_PER_SECOND / 5);

			continue;
		}

		/* If there's a protocol error, stop and abort. */
		if (server->rcls != 0)
		{
			LOG (("server->rcls = %ld err = %ld\n",server->rcls, server->err));

			smb_printerr (server->rcls, server->err);

			(*error_ptr) = error_check_smb_error;

			result = -1;
			break;
		}

		/* Bail out if this is empty. */
		if (resp_param == NULL)
			break;

		/* parse out some important return info */
		p = resp_param;
		if (is_first)
		{
			ff_dir_handle = WVAL (p, 0);

			ff_searchcount = WVAL (p, 2);
			ff_end_of_search = WVAL (p, 4);
		}
		else
		{
			ff_searchcount = WVAL (p, 0);
			ff_end_of_search = WVAL (p, 2);
		}

		LOG (("received %ld entries (end_of_search=%ld)\n",ff_searchcount, ff_end_of_search));
		if (ff_searchcount == 0)
			break;

		/* Bail out if this is empty. */
		if (resp_data == NULL)
			break;

		/* point to the data bytes */
		p = resp_data;

		/* Now we are ready to parse smb directory entries. */
		for (i = 0 ; i < ff_searchcount; i++, p += entry_length)
		{
			if(i == ff_searchcount - 1)
			{
				char * last_name;
				int len;

				ff_resume_key = DVAL(p, 0);

				smb_get_dirent_name(p,info_level,&last_name,&len);

				if(len > 0)
				{
					if(len + 1 > mask_buffer_size)
					{
						/* Grow the buffer in steps of 16 bytes,
						 * so that we won't have to reallocate it
						 * over and over again if it keeps growing
						 * in smaller portions only.
						 */
						const int grow_size_by = 16;

						D(("increasing mask; old value = %ld new value = %ld",mask_buffer_size,len + grow_size_by));

						mask_buffer_size = len + grow_size_by;
						SHOWVALUE(mask_buffer_size);

						if(mask != NULL)
							free (mask);

						mask = malloc (mask_buffer_size);
						if (mask == NULL)
						{
							LOG (("Memory allocation failed\n"));

							(*error_ptr) = ENOMEM;

							result = -1;
							goto out;
						}
					}

					memcpy (mask, last_name, len);
					mask[len] = '\0';
				}

				mask_len = len;
			}

			if (total_count < fpos)
			{
				smb_decode_long_dirent (server, p, NULL, info_level, &entry_length);
				if(entry_length == 0)
					break;

				LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n",total_count, i, fpos));
			}
			else if (total_count >= fpos + cache_size)
			{
				smb_decode_long_dirent (server, p, NULL, info_level, &entry_length);
				if(entry_length == 0)
					break;

				LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n",total_count, i, fpos));

				continue;
			}
			else
			{
				/* Skip this entry if we cannot decode the name. This could happen
				 * if the name will no fit into the buffer.
				 */
				if(!smb_decode_long_dirent (server, p, current_entry, info_level, &entry_length))
				{
					if(entry_length == 0)
						break;

					LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n",total_count, i, fpos));

					continue;
				}

				current_entry += 1;
			}

			total_count += 1;

			if(entry_length == 0)
				break;
		}

		SHOWVALUE(ff_resume_key);

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

 out:

	/* finished: not needed any more */
	if (mask != NULL)
		free (mask);

	if (resp_data != NULL)
		free (resp_data);

	if (resp_param != NULL)
		free (resp_param);

	if(result == 0)
		result = total_count - fpos;

	RETURN(result);
	return(result);
}

int
smb_proc_readdir (struct smb_server *server, const char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
{
	int result;

	if (server->protocol >= PROTOCOL_LANMAN2)
		result = smb_proc_readdir_long (server, path, fpos, cache_size, entry, error_ptr);
	else
		result = smb_proc_readdir_short (server, path, fpos, cache_size, entry, error_ptr);

	return result;
}

int
smb_proc_getattr_core (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr)
{
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	int path_size;

	LOG (("path='%s'\n", escape_name(path)));

	if(server->unicode_enabled)
		path_size = 1 + 2 * (len + 1);
	else
		path_size = 1 + len + 1;

	ASSERT( smb_payload_size(server, 0, path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBgetatr, 0, path_size);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A null-terminated string follows. */
		copy_latin1_to_utf16le(p,2 * (len+1),path,len);
	}
	else
	{
		smb_encode_ascii (p, path, len);
	}

	result = smb_request_ok (server, SMBgetatr, 10, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
			goto retry;
		else
			goto out;
	}

	entry->attr = WVAL (buf, smb_vwv0);

	/* The server only tells us just the mtime */
	entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc (DVAL (buf, smb_vwv1));

	entry->size_low = DVAL (buf, smb_vwv3);
	entry->size_high = 0;

	#if DEBUG
	{
		struct tm tm;

		seconds_to_tm(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

 out:

	return result;
}

int
smb_query_path_information(struct smb_server *server, const char *path, int len, int fid, struct smb_dirent *entry, int * error_ptr)
{
	unsigned char *outbuf = server->transmit_buffer;
	dword ext_file_attributes;
	dword end_of_file_low;
	dword end_of_file_high;
	int parameter_count;
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
			copy_latin1_to_utf16le(p,path_size,path,len);
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
		if((*error_ptr) != error_check_smb_error)
		{
			if (smb_retry (server))
				goto retry;
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

	p += 2 * sizeof(dword); /* LastWriteTime */

	entry->mtime = convert_long_date_to_time_t(p);
	p += 2 * sizeof(dword); /* LastChangeTime */

	p = smb_decode_dword(p, &ext_file_attributes);
	entry->attr = ext_file_attributes;

	p += sizeof(dword); /* Reserved */

	p += 2 * sizeof(dword); /* AllocationSize */

	p = smb_decode_dword(p, &end_of_file_low);
	(void) smb_decode_dword(p, &end_of_file_high);

	entry->size_low = end_of_file_low;
	entry->size_high = end_of_file_high;

	#if DEBUG
	{
		struct tm tm;
		QUAD entry_size_quad;

		entry_size_quad.Low		= entry->size_low;
		entry_size_quad.High	= entry->size_high;

		seconds_to_tm(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
		LOG(("size = %s (0x%08lx:0x%08lx)\n",convert_quad_to_string(&entry_size_quad),entry->size_high,entry->size_low));
		LOG(("attr = 0x%08lx\n",entry->attr));
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
		if (smb_retry (server))
			goto retry;
		else
			goto out;
	}

	entry->ctime		= date_dos2unix (WVAL (buf, smb_vwv1), WVAL (buf, smb_vwv0));
	entry->atime		= date_dos2unix (WVAL (buf, smb_vwv3), WVAL (buf, smb_vwv2));
	entry->mtime		= date_dos2unix (WVAL (buf, smb_vwv5), WVAL (buf, smb_vwv4));
	entry->wtime		= entry->mtime;
	entry->size_low		= DVAL (buf, smb_vwv6);
	entry->size_high	= 0;
	entry->attr			= WVAL (buf, smb_vwv10);

	#if DEBUG
	{
		struct tm tm;

		seconds_to_tm(entry->ctime,&tm);
		LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->atime,&tm);
		LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		seconds_to_tm(entry->wtime,&tm);
		LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
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
		if((*error_ptr) != error_check_smb_error)
		{
			if (smb_retry (server))
			{
				if(reopen_entry(server,entry,NULL) < 0)
				{
					LOG(("that didn't work.\n"));
					goto out;
				}
				else
				{
					goto retry;
				}
			}
		}

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
	dword local_time = utc2local (new_finfo->mtime);
	char *p;
	char *buf = server->transmit_buffer;
	int result;
	int path_size;

	if(server->unicode_enabled)
		path_size = 1 + 2 * (len + 1 + 1);
	else
		path_size = 1 + len + 1 + 1;

	ASSERT( smb_payload_size(server, 8, path_size) >= 0 );

 retry:

	p = smb_setup_header (server, SMBsetatr, 8, path_size);
	WSET (buf, smb_vwv0, new_finfo->attr);
	DSET (buf, smb_vwv1, local_time);

	if(server->unicode_enabled)
	{
		(*p++) = 4; /* A null-terminated string follows. */
		p += copy_latin1_to_utf16le(p,2 * (len+1),path,len);
		copy_latin1_to_utf16le(p,2 * (1),"",0);
	}
	else
	{
		p = smb_encode_ascii (p, path, len);
		(void) smb_encode_ascii (p, "", 0);
	}

	result = smb_request_ok (server, SMBsetatr, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
			goto retry;
	}

	return result;
}

/* smb_proc_setattrE: we do not retry here, because we rely on fid,
 * which would not be valid after a retry.
 */
int
smb_proc_setattrE (struct smb_server *server, word fid, struct smb_dirent *new_entry, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	word date, time_value;
	int result;

 retry:

	smb_setup_header (server, SMBsetattrE, 7, 0);

	WSET (buf, smb_vwv0, fid);

	date_unix2dos (new_entry->ctime, &time_value, &date);
	WSET (buf, smb_vwv1, date);
	WSET (buf, smb_vwv2, time_value);

	date_unix2dos (new_entry->atime, &time_value, &date);
	WSET (buf, smb_vwv3, date);
	WSET (buf, smb_vwv4, time_value);

	date_unix2dos (new_entry->mtime, &time_value, &date);
	WSET (buf, smb_vwv5, date);
	WSET (buf, smb_vwv6, time_value);

	result = smb_request_ok (server, SMBsetattrE, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server))
		{
			if(reopen_entry(server,new_entry,NULL) < 0)
				LOG(("that didn't work.\n"));
			else
				goto retry;
		}
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
		dword total_allocation_units_low;
		dword total_free_allocation_units_low;
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
			if((*error_ptr) != error_check_smb_error)
			{
				if (smb_retry (server))
					goto retry;
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

		p = smb_decode_dword (p, &total_allocation_units_low);
		p += sizeof(dword);

		SHOWVALUE(total_allocation_units_low);

		p = smb_decode_dword (p, &total_free_allocation_units_low);
		p += sizeof(dword);

		SHOWVALUE(total_free_allocation_units_low);

		p = smb_decode_dword (p, &sectors_per_allocation_unit);
		(void) smb_decode_dword (p, &bytes_per_sector);

		SHOWVALUE(bytes_per_sector);
		SHOWVALUE(sectors_per_allocation_unit);

		attr->total = total_allocation_units_low;
		attr->free = total_free_allocation_units_low;

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
			if (smb_retry (server))
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
	unsigned char password[24];
	int password_len;
	unsigned char nt_password[24];
	int nt_password_len;
	char * share_name = NULL;
	byte *packet;
	dword max_buffer_size;
	int packet_size;

	result = smb_connect (server, error_ptr);
	if (result < 0)
	{
		LOG (("could not connect to server\n"));
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
		LOG (("No memory! Bailing out.\n"));

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

		smb_encode_smb_length (packet, (byte *) p - (byte *) (packet));

		packet[0] = 0x81; /* SESSION REQUEST */

		result = smb_request (server, 0, NULL, NULL, 0, error_ptr);
		if (result < 0)
		{
			LOG (("Failed to send SESSION REQUEST.\n"));
			goto out;
		}

		if (packet[0] != 0x82)
		{
			LOG (("Did not receive positive response (err = %lx)\n",packet[0]));

			#if DEBUG
			{
				smb_dump_packet (packet);
			}
			#endif /* DEBUG */

			(*error_ptr) = error_session_request_failed;

			result = -1;
			goto out;
		}

		LOG (("Passed SESSION REQUEST.\n"));
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

	LOG (("Request SMBnegprot...\n"));

	result = smb_request_ok (server, SMBnegprot, 1, -1, error_ptr);
	if (result < 0)
	{
		LOG (("Failure requesting SMBnegprot\n"));
		goto out;
	}

	p = SMB_VWV (packet);

	p = smb_decode_word (p, &dialect_index);

	/* If the server does not support any of the listed
	 * dialects, ist must return a dialect index of 0xFFFF.
	 */
	if(dialect_index > num_prots || dialect_index == 0xFFFFU)
	{
		LOG (("Unsupported dialect\n"));

		(*error_ptr) = error_unsupported_dialect;

		result = -1;
		goto out;
	}

	server->protocol = prots[dialect_index].prot;

	LOG (("Server wants %s protocol.\n",prots[dialect_index].name));

	if (server->protocol > PROTOCOL_LANMAN1)
	{
		int user_len = strlen (server->mount_data.username)+1;
		dword server_sesskey;

		/*
		LOG (("password = %s\n",server->mount_data.password*));
		*/
		LOG (("usernam = %s\n",server->mount_data.username));
		LOG (("blkmode = %ld\n",WVAL (packet, smb_vwv5)));

		/* NT LAN Manager or newer. */
		if (server->protocol >= PROTOCOL_NT1)
		{
			server->security_mode = (*p++);

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

			memcpy(server->crypt_key,SMB_BUF(packet),server->crypt_key_length);
		}
		/* LAN Manager 2.0 or older */
		else
		{
			word blkmode;

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
			   LAN Manager 1.x/2.0 documentation both bits 0+1 being set
			   means the same thing as CAP_RAW_MODE being set. */
			if((blkmode & 3) == 3)
				server->capabilities = CAP_RAW_MODE;
		}

		SHOWVALUE(server->security_mode);

		if(server->security_mode & NEGOTIATE_ENCRYPT_PASSWORDS)
		{
			SHOWMSG("encrypted passwords required");

			memset(password,0,sizeof(password));
			strlcpy(password,server->mount_data.password,sizeof(password));

			smb_encrypt(password,server->crypt_key,password);
			password_len = 24;

			/*
			PRINTHEADER();
			PRINTF(("password: "));
			for(i = 0 ; i < 24 ; i++)
				PRINTF(("%02lx ",password[i]));
			PRINTF(("\n"));
			*/

			memset(nt_password,0,sizeof(nt_password));
			strlcpy(nt_password,server->mount_data.password,sizeof(nt_password));

			smb_nt_encrypt(nt_password,server->crypt_key,nt_password);
			nt_password_len = 24;

			/*
			PRINTHEADER();
			PRINTF(("nt_password: "));
			for(i = 0 ; i < 24 ; i++)
				PRINTF(("%02lx ",nt_password[i]));
			PRINTF(("\n"));
			*/

			/*
			PRINTHEADER();
			PRINTF(("crypt_key: "));
			for(i = 0 ; i < server->crypt_key_length ; i++)
				PRINTF(("%02lx ",server->crypt_key[i]));
			PRINTF(("\n"));
			*/
		}
		else
		{
			SHOWMSG("plain text passwords sufficient");

			password_len = strlen(server->mount_data.password)+1;
			nt_password_len = 0;
		}

		/* If in share level security then don't send a password now */
		if((server->security_mode & NEGOTIATE_USER_SECURITY) == 0)
		{
			SHOWMSG("share level security; zapping passwords");

			strcpy(password,"");
			password_len = 0;

			strcpy(nt_password,"");
			nt_password_len = 0;
		}

		SHOWVALUE(password_len);
		SHOWVALUE(nt_password_len);

		LOG (("workgroup = %s\n", server->mount_data.workgroup_name));

		/* NT LAN Manager or newer. */
		if (server->protocol >= PROTOCOL_NT1)
		{
			const char *native_os = "AmigaOS";
			const char *native_lanman = VERS;
			dword capabilities;

			SHOWMSG("server->protocol >= PROTOCOL_NT1");

			ASSERT( smb_payload_size(server, 13, user_len + password_len + nt_password_len + strlen (server->mount_data.workgroup_name)+1 + strlen (native_os)+1 + strlen (native_lanman)+1) >= 0 );

			smb_setup_header (server, SMBsesssetupX, 13, user_len + password_len + nt_password_len + strlen (server->mount_data.workgroup_name)+1 + strlen (native_os)+1 + strlen (native_lanman)+1);

			capabilities = CAP_LARGE_READX|CAP_LARGE_WRITEX|CAP_NT_FIND|CAP_LARGE_FILES;

			if(server->use_unicode && (server->capabilities & CAP_UNICODE) != 0)
			{
				SHOWMSG("Unicode support enabled");

				server->unicode_enabled = TRUE;

				capabilities |= CAP_UNICODE;
			}

			WSET (packet, smb_vwv0, 0xff);				/* AndXCommand+AndXReserved */
			WSET (packet, smb_vwv1, 0);					/* AndXOffset */
			WSET (packet, smb_vwv2, given_max_xmit);	/* MaxBufferSize */
			WSET (packet, smb_vwv3, 2);					/* MaxMpxCount */
			WSET (packet, smb_vwv4, 0);					/* VcNumber */
			DSET (packet, smb_vwv5, server_sesskey);	/* SessionKey */
			WSET (packet, smb_vwv7, password_len);		/* OEMPasswordLen */
			WSET (packet, smb_vwv8, nt_password_len);	/* UnicodePasswordLen */
			DSET (packet, smb_vwv9, 0);					/* Reserved */
			DSET (packet, smb_vwv11, capabilities);		/* Capabilities */

			p = SMB_BUF (packet);

			if(nt_password_len != 0)
			{
				SHOWMSG("adding encrypted passwords");

				memcpy (p, password, password_len);
				p += password_len;

				memcpy (p, nt_password, nt_password_len);
				p += nt_password_len;
			}
			else
			{
				SHOWMSG("adding plain text password");

				memcpy (p, server->mount_data.password, password_len);
				p += password_len;
			}

			memcpy (p, server->mount_data.username, user_len);
			p += user_len;

			strcpy (p, server->mount_data.workgroup_name);
			p += strlen (p) + 1;

			strcpy (p, native_os);
			p += strlen (p) + 1;

			strcpy (p, native_lanman);
		}
		/* LAN Manager 2.0 or older */
		else
		{
			ASSERT( smb_payload_size(server, 10, user_len + password_len) >= 0 );

			smb_setup_header (server, SMBsesssetupX, 10, user_len + password_len);

			WSET (packet, smb_vwv0, 0xff);	/* No further ANDX command */
			WSET (packet, smb_vwv1, 0);		/* ANDX offset = 0 */

			WSET (packet, smb_vwv2, given_max_xmit);	/* maximum buffer size */
			WSET (packet, smb_vwv3, 2);					/* maximum mpx count; should be copied from server */
			WSET (packet, smb_vwv4, 0); /* server->pid */
			DSET (packet, smb_vwv5, server_sesskey);
			WSET (packet, smb_vwv7, password_len);	/* case sensitive password length */
			WSET (packet, smb_vwv8, 0);	/* offset to encrypted password */

			p = SMB_BUF (packet);
			memcpy (p, server->mount_data.password, password_len);

			p += password_len;
			memcpy (p, server->mount_data.username, user_len);
		}

		result = smb_request_ok (server, SMBsesssetupX, 3, 0, error_ptr);
		if (result < 0)
		{
			LOG (("SMBsessetupX failed\n"));
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

		password_len = strlen(server->mount_data.password)+1;

		nt_password_len = 0;
	}

	if(nt_password_len > 0)
	{
		int server_name_len;
		int service_len;
		int share_name_len;
		int share_name_size;
		int padding_needed;

		server_name_len = strlen(server->mount_data.server_name);
		service_len = strlen(server->mount_data.service);

		share_name_len = 2 + server_name_len + 1 + service_len;

		share_name = malloc(share_name_len+1);
		if(share_name == NULL)
		{
			LOG (("No memory! Bailing out.\n"));

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

		if(server->unicode_enabled && (password_len % 2) == 0)
			padding_needed = 1;
		else
			padding_needed = 0;

		ASSERT( smb_payload_size(server, 4, password_len + padding_needed + share_name_size + strlen(dev)+1) >= 0 );

		smb_setup_header (server, SMBtconX, 4, password_len + padding_needed + share_name_size + strlen(dev)+1);

		WSET (packet, smb_vwv0, 0xFF);
		WSET (packet, smb_vwv3, password_len);

		p = SMB_BUF (packet);

		memcpy(p,password,password_len);
		p += password_len;

		if(padding_needed)
			(*p++) = 0;

		if(server->unicode_enabled)
			copy_latin1_to_utf16le(p,share_name_size,share_name,share_name_len);
		else
			memcpy(p,share_name,share_name_size);

		p += share_name_size;

		strcpy(p,dev);

		result = smb_request_ok (server, SMBtconX, 3, 0, error_ptr);
		if (result < 0)
		{
			SHOWVALUE(SMB_WCT(packet));

			LOG (("SMBtconX not verified.\n"));
			goto out;
		}

		SHOWVALUE(SMB_WCT(packet));

		server->tid = WVAL(packet,smb_tid);
	}
	else
	{
		word decoded_max_xmit;

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
			LOG (("SMBtcon not verified.\n"));
			goto out;
		}

		LOG (("OK! Managed to set up SMBtcon!\n"));

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

	LOG (("max_buffer_size = %ld, tid = %ld\n", max_buffer_size, server->tid));

	/* Let's get paranoid. Make sure that we can actually receive
	 * as much data as the buffer size allows, in a single consecutive
	 * buffer which follows the SMB message header.
	 */
	if(packet_size < (int)max_buffer_size)
	{
		SHOWVALUE(packet_size);

		/* We need to allocate a larger packet buffer. */
		packet_size = max_buffer_size;

		D(("packet size updated to %ld bytes\n", packet_size));

		free (server->transmit_buffer);

		server->transmit_buffer_size = packet_size;

		/* Add a bit of fudge to account for the NetBIOS session
		 * header and whatever else might show up...
		 */
		server->transmit_buffer_allocation_size = server->transmit_buffer_size + safety_margin;

		server->transmit_buffer = malloc (server->transmit_buffer_allocation_size);
		if (server->transmit_buffer == NULL)
		{
			LOG (("No memory! Bailing out.\n"));

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
		D(("maximum buffer size limited to %ld bytes\n", max_buffer_size));
	}

	server->max_buffer_size = max_buffer_size;

	LOG (("Normal exit\n"));

	result = 0;

 out:

	if(share_name != NULL)
		free(share_name);

	if(result < 0)
		server->state = CONN_INVALID;

	return result;
}

/* smb_proc_reconnect: server->transmit_buffer is allocated with
   server->max_buffer_size bytes if and only if we return >= 0 */
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

			LOG (("%s - %ld\n", err_classes[i].class, num));
			return;
		}

		err = (err_code_struct *)err_classes[i].err_msgs;

		for (j = 0; err[j].name; j++)
		{
			if (num != err[j].code)
				continue;

			report_error ("%s - %s (%s).", err_classes[i].class, err[j].name, err[j].message);

			LOG (("%s - %s (%s)\n",err_classes[i].class, err[j].name,err[j].message));
			return;
		}
	}

	report_error ("Unknown error - (%ld, %ld).", class, num);

	LOG (("Unknown error - (%ld, %ld)\n", class, num));
}
