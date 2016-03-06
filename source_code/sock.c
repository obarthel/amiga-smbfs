/*
 * $Id: sock.c,v 1.2 2009/04/14 11:32:51 obarthel Exp $
 *
 * :ts=8
 *
 * sock.c
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 * Modified by Christian Starkjohann <cs -at- hal -dot- kph -dot- tuwien -dot- ac -dot- at>
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#include "smbfs.h"

/*****************************************************************************/

#include <smb/smb_fs.h>
#include <smb/smb.h>
#include <smb/smbno.h>

/*****************************************************************************/

#include "smb_abstraction.h"

/*****************************************************************************/

/* The following is an attempt to decode the data that is received
 * and sent. Because so much of smbfs was created by reverse-engineering
 * the protocol it is difficult to say what works, and how.
 */

#if defined(DUMP_SMB)

/*****************************************************************************/

/* This can be used to enable or disable the SMB packet dump output. */
static int dump_smb_enabled;

/*****************************************************************************/

/* The command packets are identified by the command code, but the
 * contents are interpreted differently if the packets are sent by
 * the client ("From consumer") or by the server ("To consumer").
 */
enum smb_packet_source_t
{
	smb_packet_from_consumer,
	smb_packet_to_consumer
};


/*****************************************************************************/

/* Known SMB command codes. */
#define SMB_COM_CREATE_DIRECTORY 0x00
#define SMB_COM_DELETE_DIRECTORY 0x01
#define SMB_COM_OPEN 0x02
#define SMB_COM_CREATE 0x03
#define SMB_COM_CLOSE 0x04
#define SMB_COM_FLUSH 0x05
#define SMB_COM_DELETE 0x06
#define SMB_COM_RENAME 0x07
#define SMB_COM_QUERY_INFORMATION 0x08
#define SMB_COM_SET_INFORMATION 0x09
#define SMB_COM_READ 0x0A
#define SMB_COM_WRITE 0x0B
#define SMB_COM_LOCK_BYTE_RANGE 0x0C
#define SMB_COM_UNLOCK_BYTE_RANGE 0x0D
#define SMB_COM_CREATE_TEMPORARY 0x0E
#define SMB_COM_CREATE_NEW 0x0F
#define SMB_COM_CHECK_DIRECTORY 0x10
#define SMB_COM_PROCESS_EXIT 0x11
#define SMB_COM_SEEK 0x12
#define SMB_COM_LOCK_AND_READ 0x13
#define SMB_COM_WRITE_AND_UNLOCK 0x14
#define SMB_COM_READ_RAW 0x1A
#define SMB_COM_READ_MPX 0x1B
#define SMB_COM_READ_MPX_SECONDARY 0x1C
#define SMB_COM_WRITE_RAW 0x1D
#define SMB_COM_WRITE_MPX 0x1E
#define SMB_COM_WRITE_MPX_SECONDARY 0x1F
#define SMB_COM_WRITE_COMPLETE 0x20
#define SMB_COM_QUERY_SERVER 0x21
#define SMB_COM_SET_INFORMATION2 0x22
#define SMB_COM_QUERY_INFORMATION2 0x23
#define SMB_COM_LOCKING_ANDX 0x24
#define SMB_COM_TRANSACTION 0x25
#define SMB_COM_TRANSACTION_SECONDARY 0x26
#define SMB_COM_IOCTL 0x27
#define SMB_COM_IOCTL_SECONDARY 0x28
#define SMB_COM_COPY 0x29
#define SMB_COM_MOVE 0x2A
#define SMB_COM_ECHO 0x2B
#define SMB_COM_WRITE_AND_CLOSE 0x2C
#define SMB_COM_OPEN_ANDX 0x2D
#define SMB_COM_READ_ANDX 0x2E
#define SMB_COM_WRITE_ANDX 0x2F
#define SMB_COM_NEW_FILE_SIZE 0x30
#define SMB_COM_CLOSE_AND_TREE_DISC 0x31
#define SMB_COM_TRANSACTION2 0x32
#define SMB_COM_TRANSACTION2_SECONDARY 0x33
#define SMB_COM_FIND_CLOSE2 0x34
#define SMB_COM_FIND_NOTIFY_CLOSE 0x35
#define SMB_COM_TREE_CONNECT 0x70
#define SMB_COM_TREE_DISCONNECT 0x71
#define SMB_COM_NEGOTIATE 0x72
#define SMB_COM_SESSION_SETUP_ANDX 0x73
#define SMB_COM_LOGOFF_ANDX 0x74
#define SMB_COM_TREE_CONNECT_ANDX 0x75
#define SMB_COM_SECURITY_PACKAGE_ANDX 0x7E
#define SMB_COM_QUERY_INFORMATION_DISK 0x80
#define SMB_COM_SEARCH 0x81
#define SMB_COM_FIND 0x82
#define SMB_COM_FIND_UNIQUE 0x83
#define SMB_COM_FIND_CLOSE 0x84
#define SMB_COM_NT_TRANSACT 0xA0
#define SMB_COM_NT_TRANSACT_SECONDARY 0xA1
#define SMB_COM_NT_CREATE_ANDX 0xA2
#define SMB_COM_NT_CANCEL 0xA4
#define SMB_COM_NT_RENAME 0xA5
#define SMB_COM_OPEN_PRINT_FILE 0xC0
#define SMB_COM_WRITE_PRINT_FILE 0xC1
#define SMB_COM_CLOSE_PRINT_FILE 0xC2
#define SMB_COM_GET_PRINT_QUEUE 0xC3
#define SMB_COM_READ_BULK 0xD8
#define SMB_COM_WRITE_BULK 0xD9
#define SMB_COM_WRITE_BULK_DATA 0xDA
#define SMB_COM_INVALID 0xFE
#define SMB_COM_NO_ANDX_COMMAND 0xFF

struct smb_header
{
	unsigned char signature[4];	// Contains 0xFF, 'SMB'	[BYTE smb_idf[4]]
	unsigned char command;		// Command code [BYTE smb_com]
	unsigned long status;		// Error code class [BYTE smb_rcls]
	unsigned char flags;		// Reserved [BYTE smb_reh]
	unsigned short flags2;		// Error code [BYTE smb_err]
	
	struct
	{
		unsigned short pid_high;
		unsigned short signature[4];
	} extra;
	
	unsigned short tid;		// Tree ID # [WORD smb_tid]
	unsigned short pid;		// Callers process id [WORD smb_pid]
	unsigned short uid;		// User ID [WORD smb_uid]
	unsigned short mid;		// Multiplex ID [WORD smb_mid]

	int num_parameter_words;	// Count of parameter words [BYTE smb_wct]
	unsigned short * parameters;	// Variable number of parameter words [SHORT smb_wvw[..]]

	int num_data_bytes;		// Number of data bytes following [WORD smb_bcc]
	unsigned char * data;		// Variable number of data bytes [BYTE smb_data[..]]
};

struct decode_context
{
	const unsigned char *	data;
	int			offset;
	int			length;
	int			overflow;
};

static void
init_decode_context(const unsigned char * data,int length,struct decode_context * dc)
{
	dc->data	= data;
	dc->offset	= 0;
	dc->length	= length;
	dc->overflow	= 0;
}

static void
skip_bytes(struct decode_context * dc,int count)
{
	if(dc->offset + count <= dc->length)
		dc->offset += count;
	else
		dc->overflow = 1;
}

static void
skip_words(struct decode_context * dc,int count)
{
	skip_bytes(dc,count * 2);
}

static const unsigned char *
next_bytes(struct decode_context * dc,int count)
{
	const unsigned char * result;
	
	result = &dc->data[dc->offset];

	if(dc->offset + count <= dc->length)
		dc->offset += count;
	else
		dc->overflow = 1;
		
	return(result);
}

static unsigned char
next_byte(struct decode_context * dc)
{
	unsigned char result;
	
	result = dc->data[dc->offset];

	if(dc->offset <= dc->length)
		dc->offset++;
	else
		dc->overflow = 1;
		
	return(result);
}

static const unsigned short *
next_words(struct decode_context * dc,int count)
{
	return((const unsigned short *)next_bytes(dc,count * 2));
}

static unsigned short
next_word(struct decode_context * dc)
{
	unsigned short result;
	
	result = dc->data[dc->offset] | (((unsigned short)dc->data[dc->offset+1]) << 8);

	if(dc->offset + 2 <= dc->length)
		dc->offset += 2;
	else
		dc->overflow = 1;
		
	return(result);
}

static unsigned long
next_dword(struct decode_context * dc)
{
	unsigned short result;
	
	result =
		dc->data[dc->offset] |
		(((unsigned long)dc->data[dc->offset+1]) << 8) |
		(((unsigned long)dc->data[dc->offset+2]) << 16) |
		(((unsigned long)dc->data[dc->offset+3]) << 24);

	if(dc->offset + 4 <= dc->length)
		dc->offset += 4;
	else
		dc->overflow = 1;
		
	return(result);
}

static int
fill_header(const unsigned char * packet,int length,struct smb_header * header)
{
	struct decode_context dc;
	int num_bytes_read;
	
	init_decode_context(packet,length,&dc);
	
	memset(header,0,sizeof(header));
	
	memcpy(header->signature,next_bytes(&dc,4),4);
	header->command = next_byte(&dc);
	header->status = next_dword(&dc);
	header->flags = next_byte(&dc);
	header->flags2 = next_word(&dc);
	header->extra.pid_high = next_word(&dc);
	memcpy(header->extra.signature,next_words(&dc,4),sizeof(unsigned short) * 4);
	skip_words(&dc,1);
	header->tid = next_word(&dc);
	header->pid = next_word(&dc);
	header->uid = next_word(&dc);
	header->mid = next_word(&dc);

	header->num_parameter_words = next_byte(&dc);
	header->parameters = (unsigned short *)next_words(&dc,header->num_parameter_words);

	header->num_data_bytes = next_word(&dc);
	header->data = (unsigned char *)next_bytes(&dc,header->num_data_bytes);

	num_bytes_read = dc.offset;

	return(num_bytes_read);
}

static int
is_smb_andx_command(unsigned char command)
{
	static const unsigned char andx_commands[9] =
	{
		SMB_COM_LOCKING_ANDX,
		SMB_COM_OPEN_ANDX,
		SMB_COM_READ_ANDX,
		SMB_COM_WRITE_ANDX,
		SMB_COM_SESSION_SETUP_ANDX,
		SMB_COM_LOGOFF_ANDX,
		SMB_COM_TREE_CONNECT_ANDX,
		SMB_COM_SECURITY_PACKAGE_ANDX,
		SMB_COM_NT_CREATE_ANDX
	};
	
	int result = 0;
	int i;
	
	for(i = 0 ; i < 9 ; i++)
	{
		if(command == andx_commands[i])
		{
			result = 1;
			break;
		}
	}
	
	return(result);
}

static const char *
get_smb_command_name(unsigned char command)
{
	static const struct { int code; const char * name; } code_name_tab[] =
	{
		{ SMB_COM_CREATE_DIRECTORY, "CREATE_DIRECTORY" },
		{ SMB_COM_DELETE_DIRECTORY, "DELETE_DIRECTORY" },
		{ SMB_COM_OPEN, "OPEN" },
		{ SMB_COM_CREATE, "CREATE" },
		{ SMB_COM_CLOSE, "CLOSE" },
		{ SMB_COM_FLUSH, "FLUSH" },
		{ SMB_COM_DELETE, "DELETE" },
		{ SMB_COM_RENAME, "RENAME" },
		{ SMB_COM_QUERY_INFORMATION, "QUERY_INFORMATION" },
		{ SMB_COM_SET_INFORMATION, "SET_INFORMATION" },
		{ SMB_COM_READ, "READ" },
		{ SMB_COM_WRITE, "WRITE" },
		{ SMB_COM_LOCK_BYTE_RANGE, "LOCK_BYTE_RANGE" },
		{ SMB_COM_UNLOCK_BYTE_RANGE, "UNLOCK_BYTE_RANGE" },
		{ SMB_COM_CREATE_TEMPORARY, "CREATE_TEMPORARY" },
		{ SMB_COM_CREATE_NEW, "CREATE_NEW" },
		{ SMB_COM_CHECK_DIRECTORY, "CHECK_DIRECTORY" },
		{ SMB_COM_PROCESS_EXIT, "PROCESS_EXIT" },
		{ SMB_COM_SEEK, "SEEK" },
		{ SMB_COM_LOCK_AND_READ, "LOCK_AND_READ" },
		{ SMB_COM_WRITE_AND_UNLOCK, "WRITE_AND_UNLOCK" },
		{ SMB_COM_READ_RAW, "READ_RAW" },
		{ SMB_COM_READ_MPX, "READ_MPX" },
		{ SMB_COM_READ_MPX_SECONDARY, "READ_MPX_SECONDARY" },
		{ SMB_COM_WRITE_RAW, "WRITE_RAW" },
		{ SMB_COM_WRITE_MPX, "WRITE_MPX" },
		{ SMB_COM_WRITE_MPX_SECONDARY, "WRITE_MPX_SECONDARY" },
		{ SMB_COM_WRITE_COMPLETE, "WRITE_COMPLETE" },
		{ SMB_COM_QUERY_SERVER, "QUERY_SERVER" },
		{ SMB_COM_SET_INFORMATION2, "SET_INFORMATION2" },
		{ SMB_COM_QUERY_INFORMATION2, "QUERY_INFORMATION2" },
		{ SMB_COM_LOCKING_ANDX, "LOCKING_ANDX" },
		{ SMB_COM_TRANSACTION, "TRANSACTION" },
		{ SMB_COM_TRANSACTION_SECONDARY, "TRANSACTION_SECONDARY" },
		{ SMB_COM_IOCTL, "IOCTL" },
		{ SMB_COM_IOCTL_SECONDARY, "IOCTL_SECONDARY" },
		{ SMB_COM_COPY, "COPY" },
		{ SMB_COM_MOVE, "MOVE" },
		{ SMB_COM_ECHO, "ECHO" },
		{ SMB_COM_WRITE_AND_CLOSE, "WRITE_AND_CLOSE" },
		{ SMB_COM_OPEN_ANDX, "OPEN_ANDX" },
		{ SMB_COM_READ_ANDX, "READ_ANDX" },
		{ SMB_COM_WRITE_ANDX, "WRITE_ANDX" },
		{ SMB_COM_NEW_FILE_SIZE, "NEW_FILE_SIZE" },
		{ SMB_COM_CLOSE_AND_TREE_DISC, "CLOSE_AND_TREE_DISC" },
		{ SMB_COM_TRANSACTION2, "TRANSACTION2" },
		{ SMB_COM_TRANSACTION2_SECONDARY, "TRANSACTION2_SECONDARY" },
		{ SMB_COM_FIND_CLOSE2, "FIND_CLOSE2" },
		{ SMB_COM_FIND_NOTIFY_CLOSE, "FIND_NOTIFY_CLOSE" },
		{ SMB_COM_TREE_CONNECT, "TREE_CONNECT" },
		{ SMB_COM_TREE_DISCONNECT, "TREE_DISCONNECT" },
		{ SMB_COM_NEGOTIATE, "NEGOTIATE" },
		{ SMB_COM_SESSION_SETUP_ANDX, "SESSION_SETUP_ANDX" },
		{ SMB_COM_LOGOFF_ANDX, "LOGOFF_ANDX" },
		{ SMB_COM_TREE_CONNECT_ANDX, "TREE_CONNECT_ANDX" },
		{ SMB_COM_SECURITY_PACKAGE_ANDX, "SECURITY_PACKAGE_ANDX" },
		{ SMB_COM_QUERY_INFORMATION_DISK, "QUERY_INFORMATION_DISK" },
		{ SMB_COM_SEARCH, "SEARCH" },
		{ SMB_COM_FIND, "FIND" },
		{ SMB_COM_FIND_UNIQUE, "FIND_UNIQUE" },
		{ SMB_COM_FIND_CLOSE, "FIND_CLOSE" },
		{ SMB_COM_NT_TRANSACT, "NT_TRANSACT" },
		{ SMB_COM_NT_TRANSACT_SECONDARY, "NT_TRANSACT_SECONDARY" },
		{ SMB_COM_NT_CREATE_ANDX, "NT_CREATE_ANDX" },
		{ SMB_COM_NT_CANCEL, "NT_CANCEL" },
		{ SMB_COM_NT_RENAME, "NT_RENAME" },
		{ SMB_COM_OPEN_PRINT_FILE, "OPEN_PRINT_FILE" },
		{ SMB_COM_WRITE_PRINT_FILE, "WRITE_PRINT_FILE" },
		{ SMB_COM_CLOSE_PRINT_FILE, "CLOSE_PRINT_FILE" },
		{ SMB_COM_GET_PRINT_QUEUE, "GET_PRINT_QUEUE" },
		{ SMB_COM_READ_BULK, "READ_BULK" },
		{ SMB_COM_WRITE_BULK, "WRITE_BULK" },
		{ SMB_COM_WRITE_BULK_DATA, "WRITE_BULK_DATA" },
		{ SMB_COM_INVALID, "INVALID" },
		{ SMB_COM_NO_ANDX_COMMAND, "NO_ANDX_COMMAND" },
		{ -1, NULL }
	};
	
	const char * result = NULL;
	int i;
	
	for(i = 0 ; code_name_tab[i].code != -1 ; i++)
	{
		if(command == code_name_tab[i].code)
		{
			result = code_name_tab[i].name;
			break;
		}
	}
	
	return(result);
}

#define SMB_FLAGS_SERVER_TO_REDIR	0x80
#define SMB_FLAGS_REQUEST_BATCH_OPLOCK	0x40
#define SMB_FLAGS_REQUEST_OPLOCK	0x20
#define SMB_FLAGS_CANONICAL_PATHNAMES	0x10
#define SMB_FLAGS_CASELESS_PATHNAMES	0x08
#define SMB_FLAGS_CLIENT_BUF_AVAIL	0x02
#define SMB_FLAGS_SUPPORT_LOCKREAD	0x01

#define SMB_FLAGS2_UNICODE_STRINGS	0x8000
#define SMB_FLAGS2_32BIT_STATUS		0x4000
#define SMB_FLAGS2_READ_IF_EXECUTE	0x2000
#define SMB_FLAGS2_DFS_PATHNAME		0x1000
#define SMB_FLAGS2_EXTENDED_SECURITY	0x0800
#define SMB_FLAGS2_IS_LONG_NAME		0x0040
#define SMB_FLAGS2_SECURITY_SIGNATURE	0x0004
#define SMB_FLAGS2_EAS			0x0002
#define SMB_FLAGS2_KNOWS_LONG_NAMES	0x0001

struct line_buffer
{
	char line[512];
	size_t length;
};

static void
init_line_buffer(struct line_buffer *lb)
{
	lb->length = 0;
	lb->line[lb->length] = '\0';
}

static void
set_line_buffer(struct line_buffer *lb,int c,size_t len)
{
	if(len > sizeof(lb->line)-1)
		len = sizeof(lb->line)-1;

	memset(lb->line,c,len);

	lb->length = len;
	lb->line[lb->length] = '\0';
}

static void
copy_string_to_line_buffer(struct line_buffer *lb,const char *str,size_t len,size_t pos)
{
	if(pos+len > sizeof(lb->line)-1)
	{
		if(pos < sizeof(lb->line)-1)
			len = sizeof(lb->line)-1 - pos;
		else
			len = 0;
	}

	if(len > 0)
	{
		memmove(&lb->line[pos],str,len);

		if(lb->length < pos+len)
		{
			lb->length = pos+len;
			lb->line[lb->length] = '\0';
		}
	}
}

static void
add_lb_flag(struct line_buffer *lb,const char * str)
{
	size_t len = strlen(str);

	if(lb->length == 0)
	{
		if(lb->length + len < sizeof(lb->line)-1)
		{
			memcpy(&lb->line[lb->length],str,len);
			lb->length += len;

			lb->line[lb->length] = '\0';
		}
	}
	else
	{
		if(lb->length + 2 + len < sizeof(lb->line)-1)
		{
			memcpy(&lb->line[lb->length],", ",2);
			lb->length += 2;

			memcpy(&lb->line[lb->length],str,len);
			lb->length += len;

			lb->line[lb->length] = '\0';
		}
	}
}

static void
print_smb_contents(const struct smb_header * header)
{
}

static void
print_smb_header(const struct smb_header * header,int header_length,int packet_size,enum smb_packet_source_t smb_packet_source,int max_buffer_size)
{
	const char * command_name;
	struct line_buffer lb;

	command_name = get_smb_command_name(header->command);
	if(command_name != NULL)
		Printf("command = %s\n",command_name);
	else
		Printf("command = 0x%02lx\n",header->command);

	if(smb_packet_source == smb_packet_from_consumer)
		Printf("source = from consumer (client --> server)\n");
	else
		Printf("source = to consumer (client <-- server)\n");

	if(header->flags2 & SMB_FLAGS2_32BIT_STATUS)
		Printf("status = level:%ld, facility:%ld, code:%ld\n",header->status & 3,(header->status >> 4) & 4095,(header->status >> 16) & 32767);
	else
		Printf("status = class:%ld, code:%ld\n",header->status & 255,(header->status >> 16) & 32767);

	Printf("flags = ");

	init_line_buffer(&lb);

	if(header->flags & SMB_FLAGS_SERVER_TO_REDIR)
		add_lb_flag(&lb,"type=reply");
	else
		add_lb_flag(&lb,"type=request");

	if(header->flags & SMB_FLAGS_REQUEST_BATCH_OPLOCK)
		add_lb_flag(&lb,"request-batch-oplock=batch");
	else
		add_lb_flag(&lb,"request-batch-oplock=exclusive");

	if(header->flags & SMB_FLAGS_REQUEST_OPLOCK)
		add_lb_flag(&lb,"request-oplock=yes");
	else
		add_lb_flag(&lb,"request-oplock=no");

	if(header->flags & SMB_FLAGS_CANONICAL_PATHNAMES)
		add_lb_flag(&lb,"canonical-pathnames=canonical");
	else
		add_lb_flag(&lb,"canonical-pathnames=host format");

	if(header->flags & SMB_FLAGS_CASELESS_PATHNAMES)
		add_lb_flag(&lb,"caseless-pathnames=yes");
	else
		add_lb_flag(&lb,"caseless-pathnames=no");

	if(header->flags & SMB_FLAGS_CLIENT_BUF_AVAIL)
		add_lb_flag(&lb,"client-buf-avail=yes");
	else
		add_lb_flag(&lb,"client-buf-avail=no");

	if(header->flags & SMB_FLAGS_SUPPORT_LOCKREAD)
		add_lb_flag(&lb,"support-lockread=yes");
	else
		add_lb_flag(&lb,"support-lockread=no");

	Printf("%s\n",lb.line);

	Printf("flags2 = ");

	init_line_buffer(&lb);

	if(header->flags2 & SMB_FLAGS2_UNICODE_STRINGS)
		add_lb_flag(&lb,"strings=Unicode");
	else
		add_lb_flag(&lb,"strings=ASCII");

	if(header->flags2 & SMB_FLAGS2_32BIT_STATUS)
		add_lb_flag(&lb,"status-code=NT_STATUS");
	else
		add_lb_flag(&lb,"status-code=DOS error");

	if(header->flags2 & SMB_FLAGS2_READ_IF_EXECUTE)
		add_lb_flag(&lb,"read-if-execute=yes");
	else
		add_lb_flag(&lb,"read-if-execute=no");

	if(header->flags2 & SMB_FLAGS2_DFS_PATHNAME)
		add_lb_flag(&lb,"pathname=DFS");
	else
		add_lb_flag(&lb,"pathname=normal");

	if(header->flags2 & SMB_FLAGS2_EXTENDED_SECURITY)
		add_lb_flag(&lb,"security=extended");
	else
		add_lb_flag(&lb,"security=normal");

	if(header->flags2 & SMB_FLAGS2_IS_LONG_NAME)
		add_lb_flag(&lb,"names=long");
	else
		add_lb_flag(&lb,"names=8.3");

	if(header->flags2 & SMB_FLAGS2_SECURITY_SIGNATURE)
		add_lb_flag(&lb,"security-signature=MAC");
	else
		add_lb_flag(&lb,"security-signature=none");

	if(header->flags2 & SMB_FLAGS2_EAS)
		add_lb_flag(&lb,"extended-attributes=yes");
	else
		add_lb_flag(&lb,"extended-attributes=no");

	if(header->flags2 & SMB_FLAGS2_KNOWS_LONG_NAMES)
		add_lb_flag(&lb,"client-names-supported=long");
	else
		add_lb_flag(&lb,"client-names-supported=8.3");

	Printf("%s\n",lb.line);

	Printf("signature = %04lx%04lx%04lx%04lx\n",header->extra.signature[0],header->extra.signature[1],header->extra.signature[2],header->extra.signature[3]);

	Printf("tid = %04lx\n",header->tid);
	Printf("pid = %04lx\n",header->pid);
	Printf("uid = %04lx\n",header->uid);
	Printf("mid = %04lx\n",header->mid);

	Printf("parameter words = %ld\n",header->num_parameter_words);

	if(header->num_parameter_words > 0)
	{
		int i;
		int word_value;

		for(i = 0 ; i < header->num_parameter_words ; i++)
		{
			word_value = ((header->parameters[i] >> 8) & 0xff) | (((int)(header->parameters[i] & 0xff)) << 8);

			Printf("                  %04lx: %04lx (byte order = %04lx)\n",i,word_value,header->parameters[i]);
		}
	}

	Printf("data bytes = %ld\n",header->num_data_bytes);

	/* If there are any data bytes, print them like "type hex .." would. */
	if(header->num_data_bytes > 0)
	{
		extern VOID VARARGS68K SPrintf(STRPTR buffer, STRPTR formatString,...);

		const unsigned char * data_bytes = header->data;
		int num_data_bytes_left = header->num_data_bytes;
		int row_offset = 0;
		char format_buffer[20];
		char dword_buffer[20];
		int num_bytes_per_row,dword_pos;
		size_t dword_buffer_len;
		unsigned char c;
		int c_pos;

		while(num_data_bytes_left > 0)
		{
			/* The output line should be filled with blank spaces. */
			set_line_buffer(&lb,' ',60);

			/* Print the row offset (in bytes) at the start of the
			 * output line.
			 */
			SPrintf(format_buffer,"%04lx:",row_offset);

			copy_string_to_line_buffer(&lb,format_buffer,5,0);

			/* Print up to 16 bytes per row. */
			if(num_data_bytes_left > 16)
				num_bytes_per_row = 16;
			else
				num_bytes_per_row = num_data_bytes_left;

			dword_pos = 6;
			dword_buffer[0] = '\0';
			dword_buffer_len = 0;
			c_pos = 45;

			/* Print the bytes in hex format, followed by a column
			 * of the same data bytes interpreted as printable
			 * characters.
			 */
			while(num_bytes_per_row > 0)
			{
				c = (*data_bytes++);
				num_bytes_per_row--;
				row_offset++;
				num_data_bytes_left--;

				/* Convert this data byte to hexadecimal
				 * representation.
				 */
				SPrintf(format_buffer,"%02lx",c);

				strcat(dword_buffer,format_buffer);
				dword_buffer_len += 2;

				/* Is this not a printable character? If so,
				 * substitute it with '.'.
				 */
				if(c < ' ' || c == 127 || (128 <= c && c <= 160))
					c = '.';

				copy_string_to_line_buffer(&lb,(char *)&c,1,c_pos);
				c_pos++;

				/* If we have converted four bytes to hexadecimal
				 * format, put them into the output buffer.
				 */
				if(dword_buffer_len >= 8)
				{
					copy_string_to_line_buffer(&lb,dword_buffer,8,dword_pos);
					dword_pos += 9;

					dword_buffer[0] = '\0';
					dword_buffer_len = 0;
				}
			}

			/* If we did not convert a multiple of 32 bytes per row,
			 * add the last conversion buffer contents.
			 */
			if(dword_buffer_len > 0)
				copy_string_to_line_buffer(&lb,dword_buffer,dword_buffer_len,dword_pos);

			Printf("             %s\n",lb.line);
		}
	}

	Printf("length = %ld (packet size:%ld, buffer size:%ld)\n",header_length,packet_size,max_buffer_size);

	print_smb_contents(header);
}

static void
dump_smb(const char *file_name,int line_number,const void * packet,int length,enum smb_packet_source_t smb_packet_source,int max_buffer_size)
{
	if(dump_smb_enabled && length > 4 && memcmp(packet,"\xffSMB",4) == 0)
	{
		struct smb_header header;
		int num_bytes_read;
		
		num_bytes_read = fill_header(packet,length,&header);
		if(num_bytes_read <= length)
		{
			Printf("---\n");
			Printf("%s:%ld\n",file_name,line_number);

			print_smb_header(&header,num_bytes_read,length,smb_packet_source,max_buffer_size);

			Printf("---\n\n");
		}
	}
}

/*****************************************************************************/

void control_smb_dump(int enable)
{
	dump_smb_enabled = enable;
}

/*****************************************************************************/

#else

/*****************************************************************************/

void control_smb_dump(int enable)
{
}

/*****************************************************************************/

#endif /* defined(DUMP_SMB) */

/*****************************************************************************/

/* smb_receive_raw
   fs points to the correct segment, sock != NULL, target != NULL
   The smb header is only stored if want_header != 0. */
static int
smb_receive_raw (const struct smb_server *server, int sock_fd, unsigned char *target, int max_raw_length, int want_header)
{
  int len, result;
  int already_read;
  unsigned char peek_buf[4];

 re_recv:

  /* Read the NetBIOS session header (rfc-1002) */
  result = recvfrom (sock_fd, (void *) peek_buf, 4, 0, NULL, NULL);
  if (result < 0)
  {
    LOG (("smb_receive_raw: recv error = %ld\n", errno));
    result = (-errno);
    goto out;
  }

  if (result < 4)
  {
    LOG (("smb_receive_raw: got less than 4 bytes\n"));
    result = -EIO;
    goto out;
  }

  /* Check the session type. */
  switch (peek_buf[0])
  {
    /* 0x00 == session message */
    case 0x00:
    /* 0x82 == positive session response */
    case 0x82:
      break;

    /* 0x85 == session keepalive */
    case 0x85:
      LOG (("smb_receive_raw: Got SESSION KEEP ALIVE\n"));
      goto re_recv;

    /* 0x81 == session request */
    /* 0x83 == negative session response */
    /* 0x84 == retarget session response */
    default:
      LOG (("smb_receive_raw: Invalid packet 0x%02lx\n", peek_buf[0]));
      result = -EIO;
      goto out;
  }

  /* The length in the RFC NB header is the raw data length (17 bits) */
  len = (int)smb_len (peek_buf);
  if (len > max_raw_length)
  {
    LOG (("smb_receive_raw: Received length (%ld) > max_xmit (%ld)!\n", len, max_raw_length));
    result = -EIO;
    goto out;
  }

  /* Prepend the NetBIOS header to what is read? */
  if (want_header)
  {
    /* Check for buffer overflow. */
    if(len + 4 > max_raw_length)
    {
      LOG (("smb_receive_raw: Received length (%ld) > max_xmit (%ld)!\n", len, max_raw_length));
      result = -EIO;
      goto out;
    }
	
    memcpy (target, peek_buf, 4);
    target += 4;
  }

  already_read = 0;

  while (already_read < len)
  {
    result = recvfrom (sock_fd, (void *) (target + already_read), len - already_read, 0, NULL, NULL);
    if (result < 0)
    {
      LOG (("smb_receive_raw: recvfrom error = %ld\n", errno));

      result = (-errno);

      goto out;
    }

    already_read += result;
  }

  #if defined(DUMP_SMB)
  dump_smb(__FILE__,__LINE__,target,already_read,smb_packet_to_consumer,server->max_recv);
  #endif /* defined(DUMP_SMB) */

  result = already_read;

 out:

  return result;
}

/* smb_receive
   fs points to the correct segment, server != NULL, sock!=NULL */
static int
smb_receive (struct smb_server *server, int sock_fd)
{
  byte * packet = server->packet;
  int result;

  result = smb_receive_raw (server, sock_fd, packet,
                            server->max_recv - 4,  /* max_xmit in server includes NB header */
                            1); /* We want the header */
  if (result < 0)
  {
    LOG (("smb_receive: receive error: %ld\n", result));
    goto out;
  }

  server->rcls = *((unsigned char *) (packet + 9));
  server->err = WVAL (packet, 11);

  if (server->rcls != 0)
    LOG (("smb_receive: rcls=%ld, err=%ld\n", server->rcls, server->err));

 out:

  return result;
}

/* smb_receive's preconditions also apply here. */
static int
smb_receive_trans2 (struct smb_server *server, int sock_fd, int *data_len, int *param_len, char **data, char **param)
{
  unsigned char *inbuf = server->packet;
  int total_data;
  int total_param;
  int result;

  LOG (("smb_receive_trans2: enter\n"));

  (*data_len) = (*param_len) = 0;
  (*param) = (*data) = NULL;

  result = smb_receive (server, sock_fd);
  if (result < 0)
    goto fail;

  if (server->rcls != 0)
    goto fail;

  /* parse out the lengths */
  total_data = WVAL (inbuf, smb_tdrcnt);
  total_param = WVAL (inbuf, smb_tprcnt);

  if ((total_data > server->max_xmit) || (total_param > server->max_xmit))
  {
    LOG (("smb_receive_trans2: data/param too long\n"));

    result = -EIO;
    goto fail;
  }

  /* Allocate it, but only if there is something to allocate
     in the first place. ZZZ this may not be the proper approach,
     and we should return an error for 'no data'. */
  if(total_data > 0)
  {
    (*data) = malloc (total_data);
    if ((*data) == NULL)
    {
      LOG (("smb_receive_trans2: could not alloc data area\n"));

      result = -ENOMEM;
      goto fail;
    }
  }
  else
  {
    (*data) = NULL;
  }

  /* Allocate it, but only if there is something to allocate
     in the first place. ZZZ this may not be the proper approach,
     and we should return an error for 'no parameters'. */
  if(total_param > 0)
  {
    (*param) = malloc(total_param);
    if ((*param) == NULL)
    {
      LOG (("smb_receive_trans2: could not alloc param area\n"));

      result = -ENOMEM;
      goto fail;
    }
  }
  else
  {
    (*param) = NULL;
  }

  LOG (("smb_rec_trans2: total_data/param: %ld/%ld\n", total_data, total_param));

  while (1)
  {
    if (WVAL (inbuf, smb_prdisp) + WVAL (inbuf, smb_prcnt) > total_param)
    {
      LOG (("smb_receive_trans2: invalid parameters\n"));
      result = -EIO;
      goto fail;
    }

    if((*param) != NULL)
      memcpy ((*param) + WVAL (inbuf, smb_prdisp), smb_base (inbuf) + WVAL (inbuf, smb_proff), WVAL (inbuf, smb_prcnt));

    (*param_len) += WVAL (inbuf, smb_prcnt);

    if (WVAL (inbuf, smb_drdisp) + WVAL (inbuf, smb_drcnt) > total_data)
    {
      LOG (("smb_receive_trans2: invalid data block\n"));
      result = -EIO;
      goto fail;
    }

    if((*data) != NULL)
      memcpy ((*data) + WVAL (inbuf, smb_drdisp), smb_base (inbuf) + WVAL (inbuf, smb_droff), WVAL (inbuf, smb_drcnt));

    (*data_len) += WVAL (inbuf, smb_drcnt);

    LOG (("smb_rec_trans2: drcnt/prcnt: %ld/%ld\n", WVAL (inbuf, smb_drcnt), WVAL (inbuf, smb_prcnt)));

    /* parse out the total lengths again - they can shrink! */
    if ((WVAL (inbuf, smb_tdrcnt) > total_data) || (WVAL (inbuf, smb_tprcnt) > total_param))
    {
      LOG (("smb_receive_trans2: data/params grew!\n"));
      result = -EIO;
      goto fail;
    }

    total_data = WVAL (inbuf, smb_tdrcnt);
    total_param = WVAL (inbuf, smb_tprcnt);
    if (total_data <= (*data_len) && total_param <= (*param_len))
      break;

    result = smb_receive (server, sock_fd);
    if (result < 0)
      goto fail;

    if (server->rcls != 0)
    {
      result = -EIO;
      goto fail;
    }
  }

  LOG (("smb_receive_trans2: normal exit\n"));
  return 0;

 fail:

  LOG (("smb_receive_trans2: failed exit\n"));

  if((*param) != NULL)
    free (*param);

  if((*data) != NULL)
    free (*data);

  (*param) = (*data) = NULL;

  return result;
}

int
smb_release (struct smb_server *server)
{
  int result;

  if (server->mount_data.fd >= 0)
    CloseSocket (server->mount_data.fd);

  server->mount_data.fd = socket (AF_INET, SOCK_STREAM, 0);
  if (server->mount_data.fd < 0)
  {
    result = (-errno);
    goto out;
  }

  result = 0;

 out:

  return result;
}

int
smb_connect (struct smb_server *server)
{
  int sock_fd = server->mount_data.fd;
  int result;

  if (sock_fd < 0)
  {
    result = (-EBADF);
    goto out;
  }

  result = connect (sock_fd, (struct sockaddr *)&server->mount_data.addr, sizeof(struct sockaddr_in));
  if(result < 0)
    result = (-errno);

 out:

  return(result);
}

/*****************************************************************************
 *
 *  This routine was once taken from nfs, which is for udp. Here TCP does
 *  most of the ugly stuff for us (thanks, Alan!)
 *
 ****************************************************************************/

int
smb_request (struct smb_server *server)
{
  int len, result;
  int sock_fd = server->mount_data.fd;
  unsigned char *buffer = server->packet;

  if ((sock_fd < 0) || (buffer == NULL))
  {
    LOG (("smb_request: Bad server!\n"));
    result = -EBADF;
    goto out;
  }

  if (server->state != CONN_VALID)
  {
    result = -EIO;
    goto out;
  }

  len = smb_len (buffer) + 4;

  LOG (("smb_request: len = %ld cmd = 0x%lx\n", len, buffer[8]));

  #if defined(DUMP_SMB)
  dump_smb(__FILE__,__LINE__,buffer+4,len-4,smb_packet_from_consumer,server->max_recv);
  #endif /* defined(DUMP_SMB) */

  result = send (sock_fd, (void *) buffer, len, 0);
  if (result < 0)
  {
    LOG (("smb_request: send error = %ld\n", errno));

    result = (-errno);
  }
  else
  {
    result = smb_receive (server, sock_fd);
  }

 out:

  if (result < 0)
  {
    server->state = CONN_INVALID;
    smb_invalidate_all_inodes (server);
  }

  LOG (("smb_request: result = %ld\n", result));

  return (result);
}

/* This is not really a trans2 request, we assume that you only have
   one packet to send. */
int
smb_trans2_request (struct smb_server *server, int *data_len, int *param_len, char **data, char **param)
{
  int len, result;
  int sock_fd = server->mount_data.fd;
  unsigned char *buffer = server->packet;

  if (server->state != CONN_VALID)
  {
    result = -EIO;
    goto out;
  }

  len = smb_len (buffer) + 4;

  LOG (("smb_request: len = %ld cmd = 0x%02lx\n", len, buffer[8]));

  #if defined(DUMP_SMB)
  dump_smb(__FILE__,__LINE__,buffer+4,len-4,smb_packet_from_consumer,server->max_recv);
  #endif /* defined(DUMP_SMB) */

  result = send (sock_fd, (void *) buffer, len, 0);
  if (result < 0)
  {
    LOG (("smb_trans2_request: send error = %ld\n", errno));

    result = (-errno);
  }
  else
  {
    result = smb_receive_trans2 (server, sock_fd, data_len, param_len, data, param);
  }

 out:

  if (result < 0)
  {
    server->state = CONN_INVALID;
    smb_invalidate_all_inodes (server);
  }

  LOG (("smb_trans2_request: result = %ld\n", result));

  return result;
}

/* target must be in user space */
int
smb_request_read_raw (struct smb_server *server, unsigned char *target, int max_len)
{
  int len, result;
  int sock_fd = server->mount_data.fd;
  unsigned char *buffer = server->packet;

  if (server->state != CONN_VALID)
  {
    result = -EIO;
    goto out;
  }

  len = smb_len (buffer) + 4;

  LOG (("smb_request_read_raw: len = %ld cmd = 0x%02lx\n", len, buffer[8]));
  LOG (("smb_request_read_raw: target=%lx, max_len=%ld\n", (unsigned int) target, max_len));
  LOG (("smb_request_read_raw: buffer=%lx, sock=%lx\n", (unsigned int) buffer, (unsigned int) sock_fd));

  #if defined(DUMP_SMB)
  dump_smb(__FILE__,__LINE__,buffer+4,len-4,smb_packet_from_consumer,server->max_recv);
  #endif /* defined(DUMP_SMB) */

  result = send (sock_fd, (void *) buffer, len, 0);

  LOG (("smb_request_read_raw: send returned %ld\n", result));

  if (result < 0)
  {
    LOG (("smb_request_read_raw: send error = %ld\n", errno));

    result = (-errno);
  }
  else
  {
    result = smb_receive_raw (server, sock_fd, target, max_len, 0);
  }

 out:

  if (result < 0)
  {
    server->state = CONN_INVALID;
    smb_invalidate_all_inodes (server);
  }

  LOG (("smb_request_read_raw: result = %ld\n", result));

  return result;
}

/* Source must be in user space. smb_request_write_raw assumes that
   the request SMBwriteBraw has been completed successfully, so that
   we can send the raw data now. */
int
smb_request_write_raw (struct smb_server *server, unsigned const char *source, int length)
{
  int result;
  byte nb_header[4];
  int sock_fd = server->mount_data.fd;

  if (server->state != CONN_VALID)
  {
    result = -EIO;
    goto out;
  }

  smb_encode_smb_length (nb_header, length);

  result = send (sock_fd, (void *) nb_header, 4, 0);
  if (result == 4)
  {
    #if defined(DUMP_SMB)
    dump_smb(__FILE__,__LINE__,source,length,smb_packet_from_consumer,server->max_recv);
    #endif /* defined(DUMP_SMB) */

    result = send (sock_fd, (void *) source, length, 0);
    if(result < 0)
      result = (-errno);
  }
  else
  {
    if(result < 0)
      result = (-errno);
    else
      result = -EIO;
  }

  LOG (("smb_request_write_raw: send returned %ld\n", result));

  if (result == length)
    result = smb_receive (server, sock_fd);

 out:

  if (result < 0)
  {
    server->state = CONN_INVALID;

    smb_invalidate_all_inodes (server);
  }

  if (result > 0)
    result = length;

  LOG (("smb_request_write_raw: result = %ld\n", result));

  return result;
}
