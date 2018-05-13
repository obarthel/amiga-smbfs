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
	{"ERRtimeout",					88,		"The requested operation on a named pipe or an I/O device has timed out"},
	{"ERRnoresource",				89,		"No resources currently available for this SMB request"},
	{"ERRtoomanyuids",				90,		"Too many UIDs active for this SMB connection"},
	{"ERRbaduid",					91,		"The UID supplied is not known to the session, or the user identified by the UID does not have sufficient privileges"},
	{"ERROR_DIRECTORY_NOT_EMPTY",	145,	"The directory is not empty"},
	{"OBJECT_NAME_COLLISION",		183,	"Object name collision"},
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
	{"ERRdata",			23,	"Data error (CRC)"},
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

/*****************************************************************************
 *
 *  Encoding/Decoding section
 *
 *****************************************************************************/
static INLINE byte *
smb_encode_word (byte * p, word data)
{
	p[0] = data & 0x00ffU;
	p[1] = (data & 0xff00U) >> 8;
	return &p[2];
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
	strcpy (p, name);

	return p + len + 1;
}

static byte *
smb_encode_ascii (byte * p, const byte * name, int len)
{
	(*p++) = 4;
	strcpy (p, name);

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
   expressed as seconds past January 1st, 1970, local
   time zone. */
static INLINE int
utc2local (int time_value)
{
	int result;

	if(time_value > 0)
		result = time_value - GetTimeZoneDelta();
	else
		result = time_value;

	return result;
}

static INLINE int
local2utc (int time_value)
{
	int result;

	if(time_value > 0)
		result = time_value + GetTimeZoneDelta();
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

	seconds = MakeTime(&tm);

	return(seconds);
}

/* Convert linear UNIX date to a MS-DOS time/date pair. */
static void
date_unix2dos (int unix_date, unsigned short *time_value, unsigned short *date)
{
	struct tm tm;

	GMTime(unix_date,&tm);

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
				errcls,error,err_class->class,err_code->message,(-result),strerror(-result)));
		}
		else
		{
			LOG(("no proper translation for error code %ld/%ld to %ld (%s)\n",
				errcls,error,(-result),strerror(-result)));
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
	result = smb_request (server, input_payload, output_payload, payload_size, error_ptr);

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

/* smb_retry: This function should be called when smb_request_ok has
   indicated an error. If the error was indicated because the
   connection was killed, we try to reconnect. If smb_retry returns 0,
   the error was indicated for another reason, so a retry would not be
   of any use. */
static int
smb_retry (struct smb_server *server, int * error_ptr)
{
	int result = 0;

	if (server->state == CONN_VALID)
		goto out;

	smb_release (server);

	if (smb_proc_reconnect (server, error_ptr) < 0)
	{
		LOG (("smb_proc_reconnect failed\n"));
		server->state = CONN_RETRIED;
		goto out;
	}

	server->state = CONN_VALID;
	result = 1;

 out:

	return result;
}

/* smb_setup_header: We completely set up the packet. You only have to
 * insert the command-specific fields.
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

	ASSERT( smb_frame_size <= (int)server->transmit_buffer_size );

	if(smb_frame_size > (int)server->transmit_buffer_size)
		LOG (("Danger: total packet size (%ld) > transmit buffer allocation (%ld)!\n", smb_frame_size, server->transmit_buffer_size));

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
		BSET (buf, smb_flg, 0x8); /* path names are caseless */
		WSET (buf, smb_flg2, 0x3); /* extended attributes supported, long names supported */
	}

	(*p++) = wct;
	p += wct * sizeof(word);

	WSET (p, 0, bcc);

	LOG (("total packet size=%ld, max receive size=%ld, packet buffer size=%ld\n",
		p + sizeof(word) + bcc - server->transmit_buffer,
		server->max_recv,
		server->transmit_buffer_size
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
smb_proc_open (struct smb_server *server, const char *pathname, int len, struct smb_dirent *entry,int * error_ptr)
{
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	const word o_attr = aSYSTEM | aHIDDEN | aDIR;

	LOG (("path=%s\n", pathname));

 retry:

	ASSERT( smb_payload_size(server, 2, 2 + len) >= 0 );

	p = smb_setup_header (server, SMBopen, 2, 2 + len);
	WSET (buf, smb_vwv0, 0x42); /* read/write */
	WSET (buf, smb_vwv1, o_attr);
	smb_encode_ascii (p, pathname, len);

	result = smb_request_ok (server, SMBopen, 7, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;

		/* ZZZ Why is the file opened in read-only mode here? */

		if ((*error_ptr) == EACCES || ((*error_ptr) == error_check_smb_error && smb_errno(server->rcls,server->err) == EACCES))
		{
			ASSERT( smb_payload_size(server, 2, 2 + len) >= 0 );

			p = smb_setup_header (server, SMBopen, 2, 2 + len);
			WSET (buf, smb_vwv0, 0x40); /* read only */
			WSET (buf, smb_vwv1, o_attr);
			smb_encode_ascii (p, pathname, len);

			result = smb_request_ok (server, SMBopen, 7, 0, error_ptr);
			if (result < 0)
			{
				if (smb_retry (server, error_ptr))
					goto retry;

				goto out;
			}
		}
		else
		{
			goto out;
		}
	}

	/* We should now have data in vwv[0..6]. */
	entry->fileid = WVAL (buf, smb_vwv0);
	entry->attr = WVAL (buf, smb_vwv1);
	entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc (DVAL (buf, smb_vwv2));
	entry->size = DVAL (buf, smb_vwv4);
	entry->opened = 1;

	#if DEBUG
	{
		struct tm tm;

		GMTime(entry->ctime,&tm);
		LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->atime,&tm);
		LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->wtime,&tm);
		LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

 out:

	return result;
}

/* smb_proc_close: in finfo->mtime we can send a modification time to
   the server */
int
smb_proc_close (struct smb_server *server, word fileid, dword mtime, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int local_time;
	int result;

	if(mtime != 0 && mtime != 0xffffffff)
	{
		/* 0 and 0xffffffff mean: do not set mtime */
		local_time = utc2local (mtime);
	}
	else
	{
		local_time = mtime;
	}

	smb_setup_header (server, SMBclose, 3, 0);
	WSET (buf, smb_vwv0, fileid);
	DSET (buf, smb_vwv1, local_time);

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

	smb_setup_header (server, SMBread, 5, 0);

	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, count);
	DSET (buf, smb_vwv2, offset);
	WSET (buf, smb_vwv4, 0);

	LOG(("requesting %ld bytes\n", count));

	result = smb_request_ok_with_payload (server, SMBread, 5, -1, data, NULL, count, error_ptr);
	if (result < 0)
		goto out;

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
smb_proc_read_raw (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, char *data, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	ASSERT( count <= 65535 );

	smb_setup_header (server, SMBreadbraw, 8, 0);

	WSET (buf, smb_vwv0, finfo->fileid);
	DSET (buf, smb_vwv1, offset);
	WSET (buf, smb_vwv3, count); /* maxcnt */
	WSET (buf, smb_vwv4, 0); /* mincnt */
	DSET (buf, smb_vwv5, 0); /* timeout */
	WSET (buf, smb_vwv7, 0); /* reserved */

	result = smb_request_read_raw (server, data, count, error_ptr);

	return result;
}

int
smb_proc_write (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, const char *data, int * error_ptr)
{
	int result;
	char *buf = server->transmit_buffer;
	byte *p;

	ASSERT( count <= 65535 );

	p = smb_setup_header (server, SMBwrite, 5, count + 3);
	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, count);
	DSET (buf, smb_vwv2, offset);
	WSET (buf, smb_vwv4, 0);

	(*p++) = 1; /* Buffer format - this field must be 1 */
	WSET (p, 0, count); /* Data length - this field must match what the count field in the SMB header says */

	result = smb_request_ok_with_payload (server, SMBwrite, 1, 0, NULL, data, count, error_ptr);
	if (result >= 0)
		result = WVAL (buf, smb_vwv0);

	return result;
}

int
smb_proc_write_raw (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, const char *data, int * error_ptr)
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
	 * 4(timeout)+2(writemode)+4(reserved2)+2(datalength)+2(dataoffset)
	 * = 25 bytes
	 *
	 * The data part of a SMB_COM_WRITE_RAW command account for
	 * 2(bytecount)+0(pad) = 2 bytes, not including
	 * the actual payload
	 *
	 * This leaves 'max_buffer_size' - 59 for the payload.
	 */
	max_len = server->max_buffer_size;
	if(max_len > 65535)
		max_len = 65535;

	max_len -= 59 - NETBIOS_HEADER_SIZE;

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

	p = smb_setup_header (server, SMBwritebraw, server->protocol > PROTOCOL_COREPLUS ? 12 : 11, len);

	WSET (buf, smb_vwv0, finfo->fileid);
	DSET (buf, smb_vwv1, count);
	DSET (buf, smb_vwv3, offset);
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
	}
	else
	{
		WSET (buf, smb_vwv10, 0);
	}

	LOG(("requesting SMBwritebraw\n"));

	result = smb_request_ok_with_payload (server, SMBwritebraw, 1, 0, NULL, data, len, error_ptr);
	if (result < 0)
		goto out;

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
			goto out;

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
smb_proc_lseek (struct smb_server *server, struct smb_dirent *finfo, off_t offset, int mode, off_t * new_position_ptr, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

 retry:

	ASSERT( smb_payload_size(server, 4, 0) >= 0 );

	smb_setup_header (server, SMBlseek, 4, 0);

	WSET (buf, smb_vwv0, finfo->fileid);
	WSET (buf, smb_vwv1, mode);
	DSET (buf, smb_vwv2, offset);

	result = smb_request_ok (server, SMBlseek, 1, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;
	}
	else
	{
		(*new_position_ptr) = DVAL(buf, smb_vwv0);
	}

	return result;
}

/* smb_proc_lockingX: We don't chain any further packets to the initial one */
int
smb_proc_lockingX (struct smb_server *server, struct smb_dirent *finfo, struct smb_lkrng *locks, int num_entries, int mode, long timeout, int * error_ptr)
{
	int result;
	int num_locks, num_unlocks;
	char *buf = server->transmit_buffer;
	char *data;
	struct smb_lkrng *p;
	int i;

	num_locks = num_unlocks = 0;

	if (mode & 2)
		num_unlocks = num_entries;
	else
		num_locks = num_entries;

 retry:

	ASSERT( smb_payload_size(server, 8, num_entries * 10) >= 0 );

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
		if (smb_retry (server, error_ptr))
			goto retry;
	}

	return result;
}

/* smb_proc_do_create: We expect entry->attry & entry->ctime to be set. */
static int
smb_proc_do_create (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, word command, int * error_ptr)
{
	int result;
	char *p;
	char *buf = server->transmit_buffer;
	int local_time;

 retry:

	ASSERT( smb_payload_size(server, 3, len + 2) >= 0 );

	p = smb_setup_header (server, command, 3, len + 2);
	WSET (buf, smb_vwv0, entry->attr);
	local_time = utc2local (entry->ctime);
	DSET (buf, smb_vwv1, local_time);
	smb_encode_ascii (p, path, len);

	result = smb_request_ok (server, command, 1, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;

		goto out;
	}

	entry->opened = 1;
	entry->fileid = WVAL (buf, smb_vwv0);

	smb_proc_close (server, entry->fileid, entry->mtime, error_ptr);

 out:

	return result;
}

int
smb_proc_create (struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr)
{
	return smb_proc_do_create (server, path, len, entry, SMBcreate, error_ptr);
}

int
smb_proc_mv (struct smb_server *server, const char *opath, const int olen, const char *npath, const int nlen, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int result;

 retry:

	ASSERT( smb_payload_size(server, 1, olen + nlen + 4) >= 0 );

	p = smb_setup_header (server, SMBmv, 1, olen + nlen + 4);

	WSET (buf, smb_vwv0, 0);

	p = smb_encode_ascii (p, opath, olen);
	smb_encode_ascii (p, npath, olen);

	result = smb_request_ok (server, SMBmv, 0, 0, error_ptr);
	if (result < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;
	}

	return result;
}

int
smb_proc_mkdir (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	int result;
	char *p;

 retry:

	ASSERT( smb_payload_size(server, 0, 2 + len) >= 0 );

	p = smb_setup_header (server, SMBmkdir, 0, 2 + len);

	smb_encode_ascii (p, path, len);

	if ((result = smb_request_ok (server, SMBmkdir, 0, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;
	}

	return result;
}

int
smb_proc_rmdir (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	int result;
	char *p;

 retry:

	ASSERT( smb_payload_size(server, 0, 2 + len) >= 0 );

	p = smb_setup_header (server, SMBrmdir, 0, 2 + len);

	smb_encode_ascii (p, path, len);

	if ((result = smb_request_ok (server, SMBrmdir, 0, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;
	}

	return result;
}

int
smb_proc_unlink (struct smb_server *server, const char *path, const int len, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int result;

 retry:

	ASSERT( smb_payload_size(server, 1, 2 + len) >= 0 );

	p = smb_setup_header (server, SMBunlink, 1, 2 + len);

	WSET (buf, smb_vwv0, 0);

	smb_encode_ascii (p, path, len);

	if ((result = smb_request_ok (server, SMBunlink, 0, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
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

	p = smb_setup_header (server, SMBwrite, 5, 3);
	WSET (buf, smb_vwv0, fid);
	WSET (buf, smb_vwv1, 0);
	DSET (buf, smb_vwv2, length);
	WSET (buf, smb_vwv4, 0);
	smb_encode_ascii (p, "", 0);

	result = smb_request_ok (server, SMBwrite, 1, 0, error_ptr);
	if (result >= 0)
		result = DVAL(buf, smb_vwv0);

	return result;
}

static char *
smb_decode_dirent (char *p, struct smb_dirent *entry)
{
	size_t name_size;

	p += SMB_STATUS_SIZE; /* reserved (search_status) */

	entry->attr = BVAL (p, 0);
	entry->mtime = entry->atime = entry->ctime = entry->wtime = date_dos2unix (WVAL (p, 1), WVAL (p, 3));
	entry->size = DVAL (p, 5);

	name_size = 13;

	if(name_size > entry->complete_path_size-1)
		name_size = entry->complete_path_size-1;

	memcpy (entry->complete_path, p + 9, name_size);

	entry->complete_path[name_size] = '\0';

	LOG (("path = %s\n", entry->complete_path));

	#if DEBUG
	{
		struct tm tm;

		GMTime(entry->ctime,&tm);
		LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->atime,&tm);
		LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->wtime,&tm);
		LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

	return p + 22;
}

/* This routine is used to read in directory entries from the network.
   Note that it is for short directory name seeks, i.e.: protocol < PROTOCOL_LANMAN2 */
static int
smb_proc_readdir_short (struct smb_server *server, char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
{
	char *p;
	char *buf;
	int result = 0;
	int i;
	int first, total_count;
	struct smb_dirent *current_entry;
	word bcc;
	word count;
	char status[SMB_STATUS_SIZE];
	int entries_asked = (server->max_recv - 100) / SMB_DIRINFO_SIZE;
	int dirlen = strlen (path);
	char * mask = NULL;

	mask = malloc(dirlen + 4 + 1);
	if (mask == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	strcpy (mask, path);
	strcat (mask, "\\*.*");

	LOG (("SMB call readdir %ld @ %ld\n", cache_size, fpos));
	LOG (("                 mask = %s\n", mask));

	buf = server->transmit_buffer;

 retry:

	first = 1;
	total_count = 0;
	current_entry = entry;

	while (1)
	{
		if (first == 1)
		{
			ASSERT( smb_payload_size(server, 2, 5 + strlen (mask)) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, 5 + strlen (mask));
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, aDIR);
			p = smb_encode_ascii (p, mask, strlen (mask));
			(*p++) = 5;
			(void) smb_encode_word (p, 0);
		}
		else
		{
			ASSERT( smb_payload_size(server, 2, 5 + SMB_STATUS_SIZE) >= 0 );

			p = smb_setup_header (server, SMBsearch, 2, 5 + SMB_STATUS_SIZE);
			WSET (buf, smb_vwv0, entries_asked);
			WSET (buf, smb_vwv1, aDIR);
			p = smb_encode_ascii (p, "", 0);
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
				if (smb_retry (server, error_ptr))
					goto retry;

				result = -1;
				goto out;
			}
		}

		p = SMB_VWV (server->transmit_buffer);
		p = smb_decode_word (p, &count); /* vwv[0] = count-returned */
		p = smb_decode_word (p, &bcc);

		first = 0;

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
				p = smb_decode_dirent (p, current_entry);

				current_entry += 1;
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
interpret_long_date(char * p)
{
	QUAD adjust;
	QUAD long_date;
	ULONG underflow;
	time_t result;

	/* Extract the 64 bit time value. */
	long_date.Low	= DVAL(p,0);
	long_date.High	= DVAL(p,4);

	/* Divide by 10,000,000 to convert the time from 100ns
	   units into seconds. */
	divide_64_by_32(&long_date,10000000,&long_date);

	/* Adjust by 369 years (11,644,473,600 seconds) to convert
	   from the epoch beginning on January 1st 1601 to the one
	   beginning on January 1st 1970 (the Unix epoch). */
	adjust.Low	= 0xb6109100;
	adjust.High = 0x00000002;

	underflow = subtract_64_from_64_to_64(&long_date,&adjust,&long_date);

	/* If the result did not produce an underflow or overflow,
	   return the number of seconds encoded in the least
	   significant word of the result. */
	if(underflow == 0 && long_date.High == 0)
		result = long_date.Low;
	else
		result = 0;

	return(result);
}

/*****************************************************************************/

static void
smb_get_dirent_name(char *p,int level,char ** name_ptr,int * len_ptr)
{
	switch (level)
	{
		case 1: /* OS/2 understands this */

			(*name_ptr) = p + 27;
			(*len_ptr) = strlen(p + 27);
			break;

		case 2: /* this is what OS/2 uses */

			(*name_ptr) = p + 31;
			(*len_ptr) = strlen(p + 31);
			break;

		case 3: /* untested */

			(*name_ptr) = p + 33;
			(*len_ptr) = strlen(p + 33);
			break;

		case 4: /* untested */

			(*name_ptr) = p + 37;
			(*len_ptr) = strlen(p + 37);
			break;

		case 260: /* NT uses this, but also accepts 2 */

			(*name_ptr) = p + 94;
			(*len_ptr) = min (DVAL (p+60, 0), SMB_MAXNAMELEN);
			break;

		default:

			(*name_ptr) = NULL;
			(*len_ptr) = 0;
			break;
	}
}

/* interpret a long filename structure - this is mostly guesses at the
   moment. The length of the structure is returned. The structure of
   a long filename depends on the info level. 260 is used by NT and 2
   is used by OS/2. */
static char *
smb_decode_long_dirent (char *p, struct smb_dirent *finfo, int level)
{
	char *result;

	switch (level)
	{
		case 1: /* OS/2 understands this */

			#if DEBUG
			{
				char buffer[255];

				memcpy(buffer,p + 27,sizeof(buffer)-1);
				buffer[sizeof(buffer)-1] = '\0';

				LOG(("type=%ld, name='%s'\n",level,buffer));
			}
			#endif /* DEBUG */

			if (finfo != NULL)
			{
				strlcpy (finfo->complete_path, p + 27, finfo->complete_path_size);

				finfo->len		= strlen (finfo->complete_path);
				finfo->size		= DVAL (p, 16);
				finfo->attr		= BVAL (p, 24);
				finfo->ctime	= date_dos2unix (WVAL (p, 6), WVAL (p, 4));
				finfo->atime	= date_dos2unix (WVAL (p, 10), WVAL (p, 8));
				finfo->mtime	= date_dos2unix (WVAL (p, 14), WVAL (p, 12));
				finfo->wtime	= finfo->mtime;

				#if DEBUG
				{
					struct tm tm;

					GMTime(finfo->ctime,&tm);
					LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->atime,&tm);
					LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->mtime,&tm);
					LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->wtime,&tm);
					LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
				}
				#endif /* DEBUG */
			}

			result = p + 28 + BVAL (p, 26);

			break;

		case 2: /* this is what OS/2 uses */

			#if DEBUG
			{
				char buffer[255];

				memcpy(buffer,p + 31,sizeof(buffer)-1);
				buffer[sizeof(buffer)-1] = '\0';

				LOG(("type=%ld, name='%s'\n",level,buffer));
			}
			#endif /* DEBUG */

			if (finfo != NULL)
			{
				strlcpy (finfo->complete_path, p + 31, finfo->complete_path_size);

				finfo->len		= strlen (finfo->complete_path);
				finfo->size		= DVAL (p, 16);
				finfo->attr		= BVAL (p, 24);
				finfo->ctime	= date_dos2unix (WVAL (p, 6), WVAL (p, 4));
				finfo->atime	= date_dos2unix (WVAL (p, 10), WVAL (p, 8));
				finfo->mtime	= date_dos2unix (WVAL (p, 14), WVAL (p, 12));
				finfo->wtime	= finfo->mtime;

				#if DEBUG
				{
					struct tm tm;

					GMTime(finfo->ctime,&tm);
					LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->atime,&tm);
					LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->mtime,&tm);
					LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->wtime,&tm);
					LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
				}
				#endif /* DEBUG */
			}

			result = p + 32 + BVAL (p, 30);

			break;

		case 260: /* NT uses this, but also accepts 2 */

			#if DEBUG
			{
				char buffer[255];
				int len;

				len = min (DVAL (p+60, 0), sizeof(buffer)-1);

				memcpy(buffer,p+94,len);
				buffer[len] = '\0';

				LOG(("type=%ld, name='%s'\n",level,buffer));
			}
			#endif /* DEBUG */

			result = p + WVAL (p, 0);

			if (finfo != NULL)
			{
				int namelen;
				time_t swap;

				p += 4; /* next entry offset */
				p += 4; /* fileindex */
				finfo->ctime = interpret_long_date(p);
				p += 8;
				finfo->atime = interpret_long_date(p);
				p += 8;
				finfo->wtime = interpret_long_date(p);
				p += 8;
				finfo->mtime = interpret_long_date(p);
				p += 8;
				finfo->size = DVAL (p, 0);
				p += 8;
				p += 8; /* alloc size */
				finfo->attr = BVAL (p, 0);
				p += 4;
				namelen = min (DVAL (p, 0), SMB_MAXNAMELEN);
				p += 4;
				p += 4; /* EA size */
				p += 2; /* short name len? */
				p += 24; /* short name? */

				if(namelen > (int)finfo->complete_path_size-1)
					namelen = finfo->complete_path_size-1;

				/* If the modification time is not set, try to
				   substitute the write time for it. */
				if(finfo->mtime == 0)
					finfo->mtime = finfo->wtime;

				/* Swap last modification time and last write time. */
				swap = finfo->mtime;
				finfo->mtime = finfo->wtime;
				finfo->wtime = swap;

				memcpy (finfo->complete_path, p, namelen);
				finfo->complete_path[namelen] = '\0';
				finfo->len = namelen;

				#if DEBUG
				{
					struct tm tm;

					GMTime(finfo->ctime,&tm);
					LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->atime,&tm);
					LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->wtime,&tm);
					LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

					GMTime(finfo->mtime,&tm);
					LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
				}
				#endif /* DEBUG */
			}

			break;

		default:

			if (finfo != NULL)
			{
				/* I have to set times to 0 here, because I do not
				   have specs about this for all info levels. */
				finfo->ctime = finfo->mtime = finfo->wtime = finfo->atime = 0;
			}

			LOG (("Unknown long filename format %ld\n", level));

			result = p + WVAL (p, 0);

			break;
	}

	return result;
}

static int
smb_proc_readdir_long (struct smb_server *server, char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
{
	int max_matches = 512; /* this should actually be based on the max_recv value */

	/* NT uses 260, OS/2 uses 2. Both accept 1. */
	int info_level = server->protocol < PROTOCOL_NT1 ? 1 : 260;

	char *p;
	int i;
	int first;
	int total_count = 0;
	struct smb_dirent *current_entry;

	char *resp_data = NULL;
	char *resp_param = NULL;
	int resp_data_len = 0;
	int resp_param_len = 0;

	int attribute = aSYSTEM | aHIDDEN | aDIR;
	int result = 0;

	int ff_searchcount;
	int ff_eos = 0;
	int ff_dir_handle = 0;
	int ff_resume_key = 0;
	int loop_count = 0;

	unsigned char *outbuf = server->transmit_buffer;

	int dirlen = strlen (path) + 2 + 1;
	char *mask = NULL;
	int masklen;

	ENTER();

	/* ZZZ experimental 'max_matches' adjustment */
	/*
	if(info_level == 260)
		max_matches = server->max_recv / 360;
	else
		max_matches = server->max_recv / 40;
	*/

	SHOWVALUE(server->max_recv);
	SHOWVALUE(max_matches);

	mask = malloc (dirlen);
	if (mask == NULL)
	{
		LOG (("Memory allocation failed\n"));

		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	strcpy (mask, path);
	strcat (mask, "\\*");
	masklen = strlen (mask);

	LOG (("SMB call lreaddir %ld @ %ld\n", cache_size, fpos));
	LOG (("                  mask = %s\n", mask));

	resp_param = NULL;
	resp_data = NULL;

 retry:

	first = 1;
	total_count = 0;
	current_entry = entry;

	while (ff_eos == 0)
	{
		loop_count++;
		if (loop_count > 200)
		{
			LOG (("Looping in FIND_NEXT???\n"));

			(*error_ptr) = error_looping_in_find_next;

			result = -1;
			break;
		}

		memset (outbuf, 0, 39);

		ASSERT( smb_payload_size(server, 15, 5 + 12 + masklen + 1) >= 0 );

		smb_setup_header (server, SMBtrans2, 15, 5 + 12 + masklen + 1);

		WSET (outbuf, smb_tpscnt, 12 + masklen + 1);
		WSET (outbuf, smb_tdscnt, 0);
		WSET (outbuf, smb_mprcnt, 10);
		WSET (outbuf, smb_mdrcnt, server->max_recv);
		WSET (outbuf, smb_msrcnt, 0);
		WSET (outbuf, smb_flags, 0);
		DSET (outbuf, smb_timeout, 0);
		WSET (outbuf, smb_pscnt, WVAL (outbuf, smb_tpscnt));
		WSET (outbuf, smb_psoff, ((SMB_BUF (outbuf) + 3) - outbuf) - 4);
		WSET (outbuf, smb_dscnt, 0);
		WSET (outbuf, smb_dsoff, 0);
		WSET (outbuf, smb_suwcnt, 1);
		WSET (outbuf, smb_setup0, first == 1 ? TRANSACT2_FINDFIRST : TRANSACT2_FINDNEXT);

		p = SMB_BUF (outbuf);
		(*p++) = 0; /* put in a null smb_name */

		/* ZZZ the following may be unnecessary, because they
		 * likely represent random data used for alignment
		 * padding purposes.
		 */
		(*p++) = 'D';
		(*p++) = ' '; /* this was added because OS/2 does it */

		if (first != 0)
		{
			LOG (("first match\n"));
			WSET (p, 0, attribute); /* attribute */
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, 8 + 4 + 2); /* resume required + close on end + continue */
			WSET (p, 6, info_level);
			DSET (p, 8, 0);
		}
		else
		{
			LOG (("next match; ff_dir_handle=0x%lx ff_resume_key=%ld mask='%s'\n", ff_dir_handle, ff_resume_key, mask));
			WSET (p, 0, ff_dir_handle);
			WSET (p, 2, max_matches); /* max count */
			WSET (p, 4, info_level);
			DSET (p, 6, ff_resume_key);
			WSET (p, 10, 8 + 4 + 2); /* resume required + close on end + continue */
		}

		p += 12;

		if(masklen > 0)
			memcpy (p, mask, masklen);

		p += masklen;
		(*p++) = 0;
		(*p) = 0;

		result = smb_trans2_request (server, &resp_data_len, &resp_param_len, &resp_data, &resp_param, error_ptr);

		LOG (("smb_trans2_request returns %ld\n", result));

		/* If an error was flagged, check first if it's a protocol
		 * error which could handle below. Otherwise, try again.
		 */
		if (result < 0 && (*error_ptr) != error_check_smb_error)
		{
			if (smb_retry (server, error_ptr))
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

		/* ZZZ bail out if this is empty. */
		if (resp_param == NULL)
			break;

		/* parse out some important return info */
		p = resp_param;
		if (first != 0)
		{
			ff_dir_handle = WVAL (p, 0);
			ff_searchcount = WVAL (p, 2);
			ff_eos = WVAL (p, 4);
		}
		else
		{
			ff_searchcount = WVAL (p, 0);
			ff_eos = WVAL (p, 2);
		}

		LOG (("received %ld entries (eos=%ld)\n",ff_searchcount, ff_eos));
		if (ff_searchcount == 0)
			break;

		/* ZZZ bail out if this is empty. */
		if (resp_data == NULL)
			break;

		/* point to the data bytes */
		p = resp_data;

		/* Now we are ready to parse smb directory entries. */
		for (i = 0; i < ff_searchcount; i++)
		{
			if(i == ff_searchcount - 1)
			{
				char * last_name;
				int len;

				ff_resume_key = DVAL(p, 0);

				smb_get_dirent_name(p,info_level,&last_name,&len);

				if(len > 0)
				{
					#if DEBUG
					{
						char buffer[SMB_MAXNAMELEN+1];

						memcpy(buffer,last_name,len);
						buffer[len] = '\0';

						LOG(("last name = '%s'\n",buffer));
					}
					#endif /* DEBUG */

					if(len + 1 > dirlen)
					{
						/* Grow the buffer in steps of 16 bytes,
						 * so that we won't have to reallocate it
						 * over and over again if it keeps growing
						 * in smaller portions only.
						 */
						const int grow_size_by = 16;

						D(("increasing mask; old value = %ld new value = %ld",dirlen,len + grow_size_by));

						dirlen = len + grow_size_by;
						SHOWVALUE(dirlen);

						if(mask != NULL)
							free (mask);

						mask = malloc (dirlen);
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

				masklen = len;
			}

			if (total_count < fpos)
			{
				p = smb_decode_long_dirent (p, NULL, info_level);

				LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n",total_count, i, fpos));
			}
			else if (total_count >= fpos + cache_size)
			{
				p = smb_decode_long_dirent (p, NULL, info_level);

				LOG (("skipped entry; total_count = %ld, i = %ld, fpos = %ld\n",total_count, i, fpos));

				continue;
			}
			else
			{
				p = smb_decode_long_dirent (p, current_entry, info_level);

				current_entry += 1;
			}

			total_count += 1;
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

		first = 0;

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
smb_proc_readdir (struct smb_server *server, char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr)
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

	LOG (("path=%s\n", path));

 retry:

	ASSERT( smb_payload_size(server, 0, 2 + len) >= 0 );

	p = smb_setup_header (server, SMBgetatr, 0, 2 + len);
	smb_encode_ascii (p, path, len);

	if ((result = smb_request_ok (server, SMBgetatr, 10, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;

		goto out;
	}

	entry->attr = WVAL (buf, smb_vwv0);

	/* The server only tells us 1 time */
	entry->ctime = entry->atime = entry->mtime = entry->wtime = local2utc (DVAL (buf, smb_vwv1));

	entry->size = DVAL (buf, smb_vwv3);

	#if DEBUG
	{
		struct tm tm;

		GMTime(entry->ctime,&tm);
		LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->atime,&tm);
		LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->wtime,&tm);
		LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

 out:

	return result;
}

/* smb_proc_getattrE: entry->fid must be valid */
int
smb_proc_getattrE (struct smb_server *server, struct smb_dirent *entry, int * error_ptr)
{
	char *buf = server->transmit_buffer;
	int result;

	smb_setup_header (server, SMBgetattrE, 1, 0);
	WSET (buf, smb_vwv0, entry->fileid);

	if ((result = smb_request_ok (server, SMBgetattrE, 11, 0, error_ptr)) < 0)
		goto out;

	entry->ctime	= date_dos2unix (WVAL (buf, smb_vwv1), WVAL (buf, smb_vwv0));
	entry->atime	= date_dos2unix (WVAL (buf, smb_vwv3), WVAL (buf, smb_vwv2));
	entry->mtime	= date_dos2unix (WVAL (buf, smb_vwv5), WVAL (buf, smb_vwv4));
	entry->wtime	= entry->mtime;
	entry->size		= DVAL (buf, smb_vwv6);
	entry->attr		= WVAL (buf, smb_vwv10);

	#if DEBUG
	{
		struct tm tm;

		GMTime(entry->ctime,&tm);
		LOG(("ctime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->atime,&tm);
		LOG(("atime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->mtime,&tm);
		LOG(("mtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));

		GMTime(entry->wtime,&tm);
		LOG(("wtime = %ld-%02ld-%02ld %ld:%02ld:%02ld\n",tm.tm_year + 1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec));
	}
	#endif /* DEBUG */

 out:

	return result;
}

/* In core protocol, there is only 1 time to be set, we use
 * entry->mtime, to make touch work.
 */
int
smb_proc_setattr_core (struct smb_server *server, const char *path, int len, struct smb_dirent *new_finfo, int * error_ptr)
{
	char *p;
	char *buf = server->transmit_buffer;
	int result;
	int local_time;

 retry:

	ASSERT( smb_payload_size(server, 8, 4 + len) >= 0 );

	p = smb_setup_header (server, SMBsetatr, 8, 4 + len);
	WSET (buf, smb_vwv0, new_finfo->attr);
	local_time = utc2local (new_finfo->mtime);
	DSET (buf, smb_vwv1, local_time);
	p = smb_encode_ascii (p, path, len);
	(void) smb_encode_ascii (p, "", 0);

	if ((result = smb_request_ok (server, SMBsetatr, 0, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
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

	return result;
}

int
smb_proc_dskattr (struct smb_server *server, struct smb_dskattr *attr, int * error_ptr)
{
	int result;
	char *p;

 retry:

	ASSERT( smb_payload_size(server, 0, 0) >= 0 );

	smb_setup_header (server, SMBdskattr, 0, 0);

	if ((result = smb_request_ok (server, SMBdskattr, 5, 0, error_ptr)) < 0)
	{
		if (smb_retry (server, error_ptr))
			goto retry;

		goto out;
	}

	p = SMB_VWV (server->transmit_buffer);
	p = smb_decode_word (p, &attr->total);
	p = smb_decode_word (p, &attr->allocblocks);
	p = smb_decode_word (p, &attr->blocksize);
	(void) smb_decode_word (p, &attr->free);

 out:

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
	 * buffer only has some extra 512 bytes of room at the end.
	 */
	const int packet_fudge_size = 512;
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
	unsigned char full_share[SMB_MAXNAMELEN+1];
	int full_share_len;
	byte *packet;
	dword max_buffer_size;
	int packet_size;

	result = smb_connect (server, error_ptr);
	if (result < 0)
	{
		LOG (("could not smb_connect\n"));
		goto fail;
	}

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
		given_max_xmit = 65534; /* 2014/10/4 fm: use 65534 since some NASs report -1 but return max of 65534 bytes */

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
	server->transmit_buffer_allocation_size = server->transmit_buffer_size + packet_fudge_size;

	server->transmit_buffer = malloc (server->transmit_buffer_allocation_size);
	if (server->transmit_buffer == NULL)
	{
		LOG (("No memory! Bailing out.\n"));

		(*error_ptr) = ENOMEM;

		result = -1;
		goto fail;
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

		result = smb_request (server, NULL, NULL, 0, error_ptr);
		if (result < 0)
		{
			LOG (("Failed to send SESSION REQUEST.\n"));
			goto fail;
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
			goto fail;
		}

		LOG (("Passed SESSION REQUEST.\n"));
	}

	/* Now we are ready to send a SMB Negotiate Protocol packet. */
	plength = 0;
	for (i = 0; i < num_prots ; i++)
		plength += strlen (prots[i].name) + 2;

	ASSERT( smb_payload_size(server, 0, plength) >= 0 );

	smb_setup_header (server, SMBnegprot, 0, plength);

	p = SMB_BUF (packet);

	for (i = 0; i < num_prots ; i++)
		p = smb_encode_dialect (p, prots[i].name, strlen (prots[i].name));

	LOG (("Request SMBnegprot...\n"));
	if ((result = smb_request_ok (server, SMBnegprot, 1, -1, error_ptr)) < 0)
	{
		LOG (("Failure requesting SMBnegprot\n"));
		goto fail;
	}

	LOG (("Verified!\n"));

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
		goto fail;
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
			p = smb_decode_dword(p, &server->max_raw_size);
			SHOWVALUE (server->max_raw_size);
			p = smb_decode_dword(p, &server_sesskey);
			p = smb_decode_dword(p, &server->capabilities);

			/* Skip "system time" (1 qword) and "server time zone" (1 word). */
			p += 2 * sizeof(dword) + sizeof(word);

			server->crypt_key_length = (*p++);

			memcpy(server->crypt_key,SMB_BUF(packet),server->crypt_key_length);
		}
		/* LAN Manager 2.0 or older */
		else
		{
			word blkmode;

			server->security_mode = BVAL(packet, smb_vwv1);
			max_buffer_size = WVAL (packet, smb_vwv2);
			SHOWVALUE (max_buffer_size);
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
			char *OS_id = "AmigaOS";
			char *client_id = "smbfs";

			SHOWMSG("server->protocol >= PROTOCOL_NT1");

			ASSERT( smb_payload_size(server, 13, user_len + password_len + nt_password_len + strlen (server->mount_data.workgroup_name)+1 + strlen (OS_id)+1 + strlen (client_id)+1) >= 0 );

			smb_setup_header (server, SMBsesssetupX, 13, user_len + password_len + nt_password_len + strlen (server->mount_data.workgroup_name)+1 + strlen (OS_id)+1 + strlen (client_id)+1);

			WSET (packet, smb_vwv0, 0xff);
			WSET (packet, smb_vwv2, given_max_xmit);
			WSET (packet, smb_vwv3, 2);
			WSET (packet, smb_vwv4, 0); /* server->pid */
			DSET (packet, smb_vwv5, server_sesskey);
			WSET (packet, smb_vwv7, password_len);
			WSET (packet, smb_vwv8, nt_password_len);
			DSET (packet, smb_vwv9, 0);	/* reserved */
			DSET (packet, smb_vwv11, server->capabilities & 0x00800000);	/* capabilities: Unix support. */

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

			strcpy (p, OS_id);
			p += strlen (p) + 1;

			strcpy (p, client_id);
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

		if ((result = smb_request_ok (server, SMBsesssetupX, 3, 0, error_ptr)) < 0)
		{
			LOG (("SMBsessetupX failed\n"));
			goto fail;
		}

		smb_decode_word (packet + 32, &server->server_uid);
	}
	else
	{
		max_buffer_size = server->max_buffer_size;
		server->capabilities = 0;

		password_len = strlen(server->mount_data.password)+1;

		nt_password_len = 0;
	}

	if(nt_password_len > 0)
	{
		strlcpy(full_share,"//",sizeof(full_share));
		strlcat(full_share,server->mount_data.server_name,sizeof(full_share));
		strlcat(full_share,"/",sizeof(full_share));
		strlcat(full_share,server->mount_data.service,sizeof(full_share));

		full_share_len = strlen(full_share);

		for(i = 0 ; i < full_share_len ; i++)
		{
			if(full_share[i] == '/')
				full_share[i] = '\\';
		}

		StringToUpper(full_share);

		SHOWSTRING(full_share);

		ASSERT( smb_payload_size(server, 4, password_len + full_share_len+1 + strlen(dev)+1) >= 0 );

		smb_setup_header (server, SMBtconX, 4, password_len + full_share_len+1 + strlen(dev)+1);

		WSET (packet, smb_vwv0, 0xFF);
		WSET (packet, smb_vwv3, password_len);

		p = SMB_BUF (packet);

		if(nt_password_len > 0)
			memcpy(p,password,password_len);
		else
			memcpy (p, server->mount_data.password, password_len);

		p += password_len;

		memcpy(p,full_share,full_share_len+1);
		p += full_share_len+1;

		strcpy(p,dev);

		if ((result = smb_request_ok (server, SMBtconX, 3, 0, error_ptr)) < 0)
		{
			SHOWVALUE(SMB_WCT(packet));

			LOG (("SMBtconX not verified.\n"));
			goto fail;
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

		if ((result = smb_request_ok (server, SMBtcon, 2, 0, error_ptr)) < 0)
		{
			LOG (("SMBtcon not verified.\n"));
			goto fail;
		}

		LOG (("OK! Managed to set up SMBtcon!\n"));

		p = SMB_VWV (packet);
		p = smb_decode_word (p, &decoded_max_xmit);

		max_buffer_size = decoded_max_xmit;

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
		server->transmit_buffer_allocation_size = server->transmit_buffer_size + packet_fudge_size;

		server->transmit_buffer = malloc (server->transmit_buffer_allocation_size);
		if (server->transmit_buffer == NULL)
		{
			LOG (("No memory! Bailing out.\n"));

			(*error_ptr) = ENOMEM;

			result = -1;
			goto fail;
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

	return 0;

 fail:

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
			ReportError("%s - %ld.", err_classes[i].class, num);

			LOG (("%s - %ld\n", err_classes[i].class, num));
			return;
		}

		err = (err_code_struct *)err_classes[i].err_msgs;

		for (j = 0; err[j].name; j++)
		{
			if (num != err[j].code)
				continue;

			ReportError ("%s - %s (%s).", err_classes[i].class, err[j].name, err[j].message);

			LOG (("%s - %s (%s)\n",err_classes[i].class, err[j].name,err[j].message));
			return;
		}
	}

	ReportError ("Unknown error - (%ld, %ld).", class, num);

	LOG (("Unknown error - (%ld, %ld)\n", class, num));
}
