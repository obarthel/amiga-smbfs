/*
 * :ts=4
 *
 * dump_smb.c
 *
 * Written by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#include "smbfs.h"

/*****************************************************************************/

#include "dump_smb.h"

/*****************************************************************************/

/* The following is an attempt to decode the data that is received
 * and sent. Because so much of smbfs was created by reverse-engineering
 * the protocol it is difficult to say what works, and how.
 */

/*****************************************************************************/

extern VOID VARARGS68K SPrintf(STRPTR buffer, STRPTR formatString,...);

/*****************************************************************************/

/* This can be used to enable or disable the SMB packet dump output. */
static int dump_smb_enabled;

/*****************************************************************************/

/* This keeps track of which SMB_COM_TRANSACTION2 subcommand was last
 * sent to the server. The server will respond to it, but the message does
 * not contain the subcommand code of the request which started it.
 */
static int last_smb_com_transaction_subcommand = -1;

/* This keeps track of the information level specified when directory
 * contents were to be retrieved by the TRANS2_FIND_FIRST2 command.
 * The data will be returned, but it's not repeated in the
 * server response message.
 */
static int last_trans2_find_information_level = -1;

/*****************************************************************************/

static unsigned long next_data_dword(const unsigned char * data,int * offset_ptr)
{
	int offset = (*offset_ptr);
	unsigned long result;

	result =
		(((unsigned long)data[offset + 3]) << 24) |
		(((unsigned long)data[offset + 2]) << 16) |
		(((unsigned long)data[offset + 1]) <<  8) |
		  (unsigned long)data[offset + 0];

	(*offset_ptr) = offset + 4;

	return(result);
}

static void next_data_qword(const unsigned char * data,unsigned long *qwords,int * offset_ptr)
{
	qwords[1] = next_data_dword(data,offset_ptr);
	qwords[0] = next_data_dword(data,offset_ptr);
}

static unsigned short next_data_word(const unsigned char * data,int * offset_ptr)
{
	int offset = (*offset_ptr);
	unsigned short result;

	result =
		(((unsigned short)data[offset+1]) << 8) |
		  (unsigned short)data[offset+0];

	(*offset_ptr) = offset + 2;

	return(result);
}

static unsigned char next_data_byte(const unsigned char * data,int * offset_ptr)
{
	int offset = (*offset_ptr);
	unsigned char result;

	result = data[offset];

	(*offset_ptr) = offset + 1;

	return(result);
}

static const unsigned char * next_data_bytes(const unsigned char * data,int num_bytes,int * offset_ptr)
{
	int offset = (*offset_ptr);
	const unsigned char * result;

	result = &data[offset];

	(*offset_ptr) = offset + num_bytes;

	return(result);
}

/*****************************************************************************/

struct decode_context
{
	const unsigned char *	data;
	int						offset;
	int						length;
	int						overflow;
};

/*****************************************************************************/

static void
init_decode_context(const unsigned char * data,int length,struct decode_context * dc)
{
	dc->data		= data;
	dc->offset		= 0;
	dc->length		= length;
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

static const unsigned char *
next_words(struct decode_context * dc,int count)
{
	return(next_bytes(dc,count * 2));
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

/*****************************************************************************/

static int
fill_header(const unsigned char * packet,int length,struct smb_header * header)
{
	struct decode_context dc;
	int num_bytes_read;
	
	memset(header,0,sizeof(header));

	header->raw_packet_size = length;
	header->raw_packet = (char *)packet;
	
	init_decode_context(packet,length,&dc);
	
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
	header->parameter_offset = dc.offset;
	header->parameters = (unsigned char *)next_words(&dc,header->num_parameter_words);

	header->num_data_bytes = next_word(&dc);
	header->data_offset = dc.offset;
	header->data = (unsigned char *)next_bytes(&dc,header->num_data_bytes);

	num_bytes_read = dc.offset;

	return(num_bytes_read);
}

/*****************************************************************************/

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

/*****************************************************************************/

static const char *
get_smb_transaction2_subcommand_name(int command)
{
	static const struct { int code ; const char * name; } code_name_tab[] =
	{
		{ TRANS2_OPEN2, "TRANS2_OPEN2" },
		{ TRANS2_FIND_FIRST2, "TRANS2_FIND_FIRST2" },
		{ TRANS2_FIND_NEXT2, "TRANS2_FIND_NEXT2" },
		{ TRANS2_QUERY_FS_INFORMATION, "TRANS2_QUERY_FS_INFORMATION" },
		{ TRANS2_QUERY_PATH_INFORMATION, "TRANS2_QUERY_PATH_INFORMATION" },
		{ TRANS2_SET_PATH_INFORMATION, "TRANS2_SET_PATH_INFORMATION" },
		{ TRANS2_QUERY_FILE_INFORMATION, "TRANS2_QUERY_FILE_INFORMATION" },
		{ TRANS2_SET_FILE_INFORMATION, "TRANS2_SET_FILE_INFORMATION" },
		{ TRANS2_FSCTL, "TRANS2_FSCTL" },
		{ TRANS2_IOCTL2, "TRANS2_IOCTL2" },
		{ TRANS2_FIND_NOTIFY_FIRST, "TRANS2_FIND_NOTIFY_FIRST" },
		{ TRANS2_FIND_NOTIFY_NEXT, "TRANS2_FIND_NOTIFY_NEXT" },
		{ TRANS2_CREATE_DIRECTORY, "TRANS2_CREATE_DIRECTORY" },
		{ TRANS2_SESSION_SETUP, "TRANS2_SESSION_SETUP" },
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

/*****************************************************************************/

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

/*****************************************************************************/

struct line_buffer
{
	char line[512];
	size_t length;
};

/*****************************************************************************/

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

/*****************************************************************************/

static void
print_smb_data(struct line_buffer * lb,int num_data_bytes_left,const unsigned char * data_bytes)
{
	if(num_data_bytes_left > 0)
	{
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
			set_line_buffer(lb,' ',60);

			/* Print the row offset (in bytes) at the start of the
			 * output line.
			 */
			SPrintf(format_buffer,"%04lx:",row_offset);

			copy_string_to_line_buffer(lb,format_buffer,5,0);

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

				copy_string_to_line_buffer(lb,(char *)&c,1,c_pos);
				c_pos++;

				/* If we have converted four bytes to hexadecimal
				 * format, put them into the output buffer.
				 */
				if(dword_buffer_len >= 8)
				{
					copy_string_to_line_buffer(lb,dword_buffer,8,dword_pos);
					dword_pos += 9;

					dword_buffer[0] = '\0';
					dword_buffer_len = 0;
				}
			}

			/* If we did not convert a multiple of 32 bytes per row,
			 * add the last conversion buffer contents.
			 */
			if(dword_buffer_len > 0)
				copy_string_to_line_buffer(lb,dword_buffer,dword_buffer_len,dword_pos);

			Printf("             %s\n",lb->line);
		}
	}
}

/*****************************************************************************/

static void
print_smb_transaction2_subcommand(int command,enum smb_packet_source_t smb_packet_source,int num_parameter_bytes,const unsigned char * parameters,int num_data_bytes,const unsigned char * data)
{
	if(command == TRANS2_FIND_FIRST2 && smb_packet_source == smb_packet_from_consumer)
	{
		int search_attributes;
		int search_count;
		int flags;
		int information_level;
		unsigned long search_storage_type;
		const char * file_name;
		int offset = 0;

		search_attributes = next_data_word(parameters,&offset);
		Printf("search attributes = 0x%04lx\n",search_attributes);

		if(search_attributes & 0x0100)
			Printf("                    SMB_SEARCH_ATTRIBUTE_READONLY\n");

		if(search_attributes & 0x0200)
			Printf("                    SMB_SEARCH_ATTRIBUTE_HIDDEN\n");

		if(search_attributes & 0x0400)
			Printf("                    SMB_SEARCH_ATTRIBUTE_SYSTEM\n");

		if(search_attributes & 0x1000)
			Printf("                    SMB_SEARCH_ATTRIBUTE_DIRECTORY\n");

		if(search_attributes & 0x2000)
			Printf("                    SMB_SEARCH_ATTRIBUTE_ARCHIVE\n");

		search_count = next_data_word(parameters,&offset);
		Printf("search count = %ld\n",search_count);

		flags = next_data_word(parameters,&offset);
		Printf("flags = 0x%04lx\n",flags);

		if(flags & 0x0001)
			Printf("        SMB_FIND_CLOSE_AFTER_REQUEST\n");

		if(flags & 0x0002)
			Printf("        SMB_FIND_CLOSE_AT_EOS\n");

		if(flags & 0x0004)
			Printf("        SMB_FIND_RETURN_RESUME_KEYS\n");

		if(flags & 0x0008)
			Printf("        SMB_FIND_CONTINUE_FROM_LAST\n");

		if(flags & 0x0010)
			Printf("        SMB_FIND_WITH_BACKUP_INTENT\n");

		information_level = next_data_word(parameters,&offset);
		Printf("information level = 0x%04lx\n",information_level);

		last_trans2_find_information_level = information_level;

		if (information_level == 0x0001)
			Printf("                    SMB_INFO_STANDARD\n");
		else if (information_level == 0x0002)
			Printf("                    SMB_INFO_QUERY_EA_SIZE\n");
		else if (information_level == 0x0003)
			Printf("                    SMB_INFO_QUERY_EAS_FROM_LIST\n");
		else if (information_level == 0x0101)
			Printf("                    SMB_FIND_FILE_DIRECTORY_INFO\n");
		else if (information_level == 0x0102)
			Printf("                    SMB_FIND_FILE_FULL_DIRECTORY_INFO\n");
		else if (information_level == 0x0103)
			Printf("                    SMB_FIND_FILE_NAMES_INFO\n");
		else if (information_level == 0x0104)
			Printf("                    SMB_FIND_FILE_BOTH_DIRECTORY_INFO\n");

		search_storage_type = next_data_dword(parameters,&offset);
		Printf("search_storage_type = 0x%08lx\n",search_storage_type);

		if(search_storage_type == 0x00000001)
			Printf("                      FILE_DIRECTORY_ONLY\n");

		if(search_storage_type == 0x00000040)
			Printf("                      FILE_NON_DIRECTORY_FILE\n");

		file_name = next_data_bytes(parameters,0,&offset);

		Printf("file name = '%s'\n",file_name);

		/* ZZZ need to deal with the 'data' provided if
		 * information_level == SMB_INFO_QUERY_EAS_FROM_LIST.
		 */
	}
	else if (command == TRANS2_FIND_NEXT2 && smb_packet_source == smb_packet_from_consumer)
	{
		int sid;
		int search_count;
		unsigned long resume_key;
		int flags;
		int information_level;
		const char * file_name;
		int offset = 0;

		sid = next_data_word(parameters,&offset);

		Printf("sid = 0x%04lx\n",sid);

		search_count = next_data_word(parameters,&offset);
		Printf("search count = %ld\n",search_count);

		information_level = next_data_word(parameters,&offset);
		Printf("information level = 0x%04lx\n",information_level);

		last_trans2_find_information_level = information_level;

		if (information_level == 0x0001)
			Printf("                    SMB_INFO_STANDARD\n");
		else if (information_level == 0x0002)
			Printf("                    SMB_INFO_QUERY_EA_SIZE\n");
		else if (information_level == 0x0003)
			Printf("                    SMB_INFO_QUERY_EAS_FROM_LIST\n");
		else if (information_level == 0x0101)
			Printf("                    SMB_FIND_FILE_DIRECTORY_INFO\n");
		else if (information_level == 0x0102)
			Printf("                    SMB_FIND_FILE_FULL_DIRECTORY_INFO\n");
		else if (information_level == 0x0103)
			Printf("                    SMB_FIND_FILE_NAMES_INFO\n");
		else if (information_level == 0x0104)
			Printf("                    SMB_FIND_FILE_BOTH_DIRECTORY_INFO\n");

		resume_key = next_data_dword(parameters,&offset);
		Printf("resume_key = 0x%08lx\n",resume_key);

		flags = next_data_word(parameters,&offset);
		Printf("flags = 0x%04lx\n",flags);

		if(flags & 0x0001)
			Printf("        SMB_FIND_CLOSE_AFTER_REQUEST\n");

		if(flags & 0x0002)
			Printf("        SMB_FIND_CLOSE_AT_EOS\n");

		if(flags & 0x0004)
			Printf("        SMB_FIND_RETURN_RESUME_KEYS\n");

		if(flags & 0x0008)
			Printf("        SMB_FIND_CONTINUE_FROM_LAST\n");

		if(flags & 0x0010)
			Printf("        SMB_FIND_WITH_BACKUP_INTENT\n");

		file_name = next_data_bytes(parameters,0,&offset);

		Printf("file name = '%s'\n",file_name);

		/* ZZZ need to deal with the 'data' provided if
		 * information_level == SMB_INFO_QUERY_EAS_FROM_LIST.
		 */
	}
	else if (smb_packet_source == smb_packet_to_consumer && (command == TRANS2_FIND_FIRST2 || command == TRANS2_FIND_NEXT2))
	{
		int sid;
		int search_count;
		int end_of_search;
		int ea_error_offset;
		int last_name_offset;
		int offset = 0;

		if(command == TRANS2_FIND_FIRST2)
		{
			sid = next_data_word(parameters,&offset);
			Printf("sid = %ld\n",sid);
		}

		search_count = next_data_word(parameters,&offset);
		Printf("search count = %ld\n",search_count);

		end_of_search = next_data_word(parameters,&offset);
		Printf("end of search = 0x%04lx\n",end_of_search);

		ea_error_offset = next_data_word(parameters,&offset);
		Printf("ea error offset = 0x%04lx\n",ea_error_offset);

		last_name_offset = next_data_word(parameters,&offset);
		Printf("last name offset = 0x%04lx\n",last_name_offset);

		/* SMB_FIND_FILE_BOTH_DIRECTORY_INFO */
		if(num_data_bytes > 0 && last_trans2_find_information_level == 0x0104)
		{
			unsigned long next_entry_offset;
			unsigned long file_index;
			unsigned long creation_time[2];	// FILETIME
			unsigned long last_access_time[2];	// FILETIME
			unsigned long last_write_time[2];	// FILETIME
			unsigned long last_change_time[2];	// FILETIME
			unsigned long end_of_file[2];	// LARGE_INTEGER
			unsigned long allocation_size[2];	// LARGE_INTEGER
			unsigned long ext_file_attributes;	// SMB_EXT_FILE_ATTR
			unsigned long file_name_length;
			unsigned long ea_size;
			int short_name_length;	// UCHAR
			int reserved;	// UCHAR
			const char * short_name; // WCHAR
			const char * file_name; // SMB_STRING
			struct line_buffer lb;
			int unicode_char;
			int unicode_offset;
			int output_offset;
			int entry_count = 0;
			int entry_offset = 0;
			int next_offset;

			while(entry_offset < num_data_bytes && entry_count < search_count)
			{
				Printf("directory entry [%ld]:\n",entry_count++);

				next_offset = entry_offset;

				next_entry_offset = next_data_dword(data,&entry_offset);

				next_offset += next_entry_offset;

				file_index = next_data_dword(data,&entry_offset);
				next_data_qword(data,creation_time,&entry_offset);
				next_data_qword(data,last_access_time,&entry_offset);
				next_data_qword(data,last_write_time,&entry_offset);
				next_data_qword(data,last_change_time,&entry_offset);
				next_data_qword(data,end_of_file,&entry_offset);
				next_data_qword(data,allocation_size,&entry_offset);
				ext_file_attributes = next_data_dword(data,&entry_offset);
				file_name_length = next_data_dword(data,&entry_offset);
				ea_size = next_data_dword(data,&entry_offset);
				short_name_length = next_data_byte(data,&entry_offset);
				reserved = next_data_byte(data,&entry_offset);
				short_name = next_data_bytes(data,24,&entry_offset);
				file_name = next_data_bytes(data,0,&entry_offset);

				Printf("\tnext entry offset = %ld\n",next_entry_offset);
				Printf("\tfile index = 0x%08lx\n",file_index);
				Printf("\tcreation time = 0x%08lx%08lx\n",creation_time[0],creation_time[1]);
				Printf("\tlast access time = 0x%08lx%08lx\n",last_access_time[0],last_access_time[1]);
				Printf("\tlast change time = 0x%08lx%08lx\n",last_change_time[0],last_change_time[1]);
				Printf("\tend of file = %lu (0x%08lx%08lx)\n",end_of_file[1],end_of_file[0],end_of_file[1]);
				Printf("\tallocation size = %lu (0x%08lx%08lx)\n",allocation_size[1],allocation_size[0],allocation_size[1]);

				Printf("\text file attributes = 0x%08lx\n",ext_file_attributes);

				if(ext_file_attributes & 0x00000001)
					Printf("\t                      ATTR_READONLY\n");

				if(ext_file_attributes & 0x00000002)
					Printf("\t                      ATTR_HIDDEN\n");

				if(ext_file_attributes & 0x00000004)
					Printf("\t                      ATTR_SYSTEM\n");

				if(ext_file_attributes & 0x00000010)
					Printf("\t                      ATTR_DIRECTORY\n");

				if(ext_file_attributes & 0x00000020)
					Printf("\t                      ATTR_ARCHIVE\n");

				if(ext_file_attributes & 0x00000080)
					Printf("\t                      ATTR_NORMAL\n");

				if(ext_file_attributes & 0x00000100)
					Printf("\t                      ATTR_TEMPORARY\n");

				if(ext_file_attributes & 0x00000800)
					Printf("\t                      ATTR_COMPRESSED\n");

				if(ext_file_attributes & 0x01000000)
					Printf("\t                      POSIX_SEMANTICS\n");

				if(ext_file_attributes & 0x02000000)
					Printf("\t                      BACKUP_SEMANTICS\n");

				if(ext_file_attributes & 0x04000000)
					Printf("\t                      DELETE_ON_CLOSE\n");

				if(ext_file_attributes & 0x08000000)
					Printf("\t                      SEQUENTIAL_SCAN\n");

				if(ext_file_attributes & 0x10000000)
					Printf("\t                      RANDOM_ACCESS\n");

				if(ext_file_attributes & 0x20000000)
					Printf("\t                      NO_BUFFERING\n");

				if(ext_file_attributes & 0x80000000)
					Printf("\t                      WRITE_THROUGH\n");

				Printf("\tfile name length = %ld\n",file_name_length);
				Printf("\tea size = %ld\n",ea_size);
				Printf("\tshort name length = %ld\n",short_name_length);
				Printf("\treserved = 0x%02lx\n",reserved);

				if(short_name_length > 0)
				{
					unicode_offset = 0;
					output_offset = 0;
					init_line_buffer(&lb);

					while(unicode_offset < short_name_length)
					{
						unicode_char = next_data_word(short_name,&unicode_offset);
						if(unicode_char == 0)
							break;

						if(' ' <= unicode_char && unicode_char < 127)
						{
							char c = unicode_char;

							copy_string_to_line_buffer(&lb,&c,1,output_offset);
							output_offset++;
						}
						else
						{
							char code_string[40];

							SPrintf(code_string,"<%02lx%02ld>",unicode_char >> 8,unicode_char & 0xff);

							copy_string_to_line_buffer(&lb,code_string,strlen(code_string),output_offset);
							output_offset += strlen(code_string);
						}
					}
					
					Printf("\tshort name = '%s'\n",lb.line);
				}

				if(file_name_length > 0)
					Printf("\tfile name = '%s'\n",file_name);

				entry_offset = next_offset;
			}
		}
		/* SMB_INFO_STANDARD */
		else if (num_data_bytes > 0 && last_trans2_find_information_level == 0x0001)
		{
			unsigned long resume_key;
			unsigned short creation_date;
			unsigned short creation_time;
			unsigned short last_access_date;
			unsigned short last_access_time;
			unsigned short last_write_date;
			unsigned short last_write_time;
			unsigned long file_data_size;
			unsigned long allocation_size;
			unsigned short file_attributes;
			unsigned char file_name_length;
			const char * file_name;
			int entry_count = 0;
			int entry_offset = 0;

			while(entry_offset < num_data_bytes && entry_count < search_count)
			{
				Printf("directory entry [%ld]:\n",entry_count++);

				resume_key = next_data_dword(data,&entry_offset);
				creation_date = next_data_word(data,&entry_offset);
				creation_time = next_data_word(data,&entry_offset);
				last_access_date = next_data_word(data,&entry_offset);
				last_access_time = next_data_word(data,&entry_offset);
				last_write_date = next_data_word(data,&entry_offset);
				last_write_time = next_data_word(data,&entry_offset);
				file_data_size = next_data_dword(data,&entry_offset);
				allocation_size = next_data_dword(data,&entry_offset);
				file_attributes = next_data_dword(data,&entry_offset);
				file_name_length = next_data_byte(data,&entry_offset);
				file_name = (char *)next_data_bytes(data,file_name_length,&entry_offset);

				Printf("\tresume key = 0x%08lx\n",resume_key);
				Printf("\tcreation date = %lu\n",creation_date);
				Printf("\tcreation time = %lu\n",creation_time);
				Printf("\tlast access date = %lu\n",last_access_date);
				Printf("\tlast access time = %lu\n",last_access_time);
				Printf("\tlast write date = %lu\n",last_write_date);
				Printf("\tlast write time = %lu\n",last_write_time);
				Printf("\tfile data size = %lu\n",file_data_size);
				Printf("\tallocation size = %lu\n",allocation_size);
				Printf("\tfile attributes = 0x%08lx\n",file_attributes);

				if((file_attributes & 0x001f) == 0)
					Printf("\t                  SMB_FILE_ATTRIBUTE_NORMAL\n");

				if(file_attributes & 0x0001)
					Printf("\t                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

				if(file_attributes & 0x0002)
					Printf("\t                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

				if(file_attributes & 0x0004)
					Printf("\t                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

				if(file_attributes & 0x0008)
					Printf("\t                  SMB_FILE_ATTRIBUTE_VOLUME\n");

				if(file_attributes & 0x0010)
					Printf("\t                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

				if(file_attributes & 0x0020)
					Printf("\t                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

				Printf("\tfile name length = %ld\n",file_name_length);
				Printf("\tfile name = '%s'\n",file_name);
			}
		}
	}
}

/*****************************************************************************/

/* SMB commands used by smbfs 1.60 and beyond
 *
#define SMBmkdir		0x00	// create directory
#define SMBrmdir		0x01	// delete directory
#define SMBopen			0x02	// open file
#define SMBcreate		0x03	// create file
#define SMBclose		0x04	// close file
#define SMBunlink		0x06	// delete file
#define SMBmv			0x07	// rename file
#define SMBgetatr		0x08	// get file attributes
#define SMBsetatr		0x09	// set file attributes
#define SMBread			0x0A	// read from file
#define SMBwrite		0x0B	// write to file
#define SMBlseek		0x12	// seek
#define SMBtcon			0x70	// tree connect
#define SMBtconX		0x75	// tree connect and X
#define SMBnegprot		0x72	// negotiate protocol
#define SMBdskattr		0x80	// get disk attributes
#define SMBsearch		0x81	// search directory

// Core+ protocol
#define SMBreadbraw		0x1a	// read a block of data with no smb header
#define SMBwritebraw	0x1d	// write a block of data with no smb header
#define SMBwritec		0x20	// secondary write request

// dos extended protocol
#define SMBsetattrE		0x22	// set file attributes expanded
#define SMBgetattrE		0x23	// get file attributes expanded
#define SMBlockingX		0x24	// lock/unlock byte ranges and X
#define SMBsesssetupX	0x73	// Session Set Up & X (including User Logon)


// Extended 2.0 protocol
#define SMBtrans2		0x32	// TRANS2 protocol set

// these are the TRANS2 sub commands
#define TRANSACT2_FINDFIRST	1
#define TRANSACT2_FINDNEXT	2
*/

/*****************************************************************************/

/* SMB commands supported so far:
 *
 * CREATE_DIRECTORY (SMBmkdir, 0x00)
 * DELETE_DIRECTORY (SMBrmdir, 0x01)
 * OPEN (SMBopen, 0x02)
 * CREATE (SMBcreate, 0x03)
 * CLOSE (SMBclose, 0x04)
 * DELETE (SMBunlink, 0x06)
 * RENAME (SMBmv, 0x07)
 * QUERY_INFORMATION (SMBgetatr, 0x08)
 * SET_INFORMATION (SMBsetatr, 0x09)
 * READ (SMBread, 0x0A)
 * WRITE (SMBwrite, 0x0B)
 * SEEK (SMBlseek, 0x12)
 * READ_RAW (SMBreadbraw, 0x1A)
 * SMB_COM_WRITE_RAW (SMBwritebraw, 0x1D)
 * SMB_COM_WRITE_COMPLETE (SMBwritec, 0x20)
 * SET_INFORMATION2 (SMBsetattrE, 0x22)
 * QUERY_INFORMATION2 (SMBgetattrE, 0x23)
 * LOCKING_ANDX (SMBlockingX, 0x24)
 * TRANSACTION2 (SMBtrans2, 0x32)
 * TREE_CONNECT (SMBtcon, 0x70)
 * NEGOTIATE (SMBnegprot, 0x72)
 * SESSION_SETUP_AND (SMBsesssetupX, 0x73)
 * TREE_CONNECT_ANDX (SMBtconX, 0x75)
 * QUERY_INFORMATION_DISK (SMBdskattr, 0x80)
 * SEARCH (SMBsearch, 0x81)
 */
static void
print_smb_contents(const struct smb_header * header,int command,enum smb_packet_source_t smb_packet_source,int num_parameter_words,const unsigned char * parameters,int num_data_bytes,const unsigned char * data)
{
	unsigned short vwv[256];
	int i,j;
	
	if(num_parameter_words > 255)
		num_parameter_words = 255;

	for(i = j = 0 ; i < num_parameter_words ; i++, j += 2)
		vwv[i] = (((int)parameters[j+1]) << 8) + parameters[j];

	if (command == SMB_COM_CREATE_DIRECTORY)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];

			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			Printf("buffer format = %ld\n",filename[0]);
			Printf("directory name = '%s'\n",filename+1);
		}
	}
	else if (command == SMB_COM_DELETE_DIRECTORY)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];

			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			Printf("buffer format = %ld\n",filename[0]);
			Printf("directory name = '%s'\n",filename+1);
		}
	}
	else if (command == SMB_COM_OPEN)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];
			int access_mode;
			int search_attribute;

			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			access_mode = vwv[0];
			Printf("access mode = 0x%04lx\n",access_mode);

			switch(access_mode & 0x0007)
			{
				case 0:

					Printf("              Open for reading\n");
					break;

				case 1:

					Printf("              Open for writing\n");
					break;

				case 2:

					Printf("              Open for reading and writing\n");
					break;

				case 3:

					Printf("              Open for execution\n");
					break;

				default:

					break;
			}

			switch((access_mode & 0x0070) >> 4)
			{
				case 0:

					Printf("              Compatibility mode\n");
					break;

				case 1:

					Printf("              Deny read/write/execute others (exclusive use requested)\n");
					break;

				case 2:

					Printf("              Deny write to others\n");
					break;

				case 3:

					Printf("              Deny read/execute to others\n");
					break;

				case 4:

					Printf("              Deny nothing to others\n");
					break;

				default:

					break;
			}

			switch((access_mode & 0x0700) >> 8)
			{
				case 0:

					Printf("              Unknown locality of reference\n");
					break;

				case 1:

					Printf("              Mainly sequential access\n");
					break;

				case 2:

					Printf("              Mainly random access\n");
					break;

				case 3:

					Printf("              Random access with some locality\n");
					break;

				default:

					break;
			}

			if(access_mode & 0x1000)
				Printf("              Perform caching on file\n");
			else
				Printf("              Do not cache the file\n");

			if(access_mode & 0x4000)
				Printf("              No read ahead or write behind is allowed on this file or device\n");

			search_attribute = vwv[1];
			Printf("search attribute = 0x%04lx\n",search_attribute);

			if(search_attribute & 0x0100)
				Printf("                   SMB_SEARCH_ATTRIBUTE_READONLY\n");

			if(search_attribute & 0x0200)
				Printf("                   SMB_SEARCH_ATTRIBUTE_HIDDEN\n");

			if(search_attribute & 0x0400)
				Printf("                   SMB_SEARCH_ATTRIBUTE_SYSTEM\n");

			if(search_attribute & 0x1000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_DIRECTORY\n");

			if(search_attribute & 0x2000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_ARCHIVE\n");

			Printf("buffer format = %ld\n",filename[0]);
			Printf("file pathname = '%s'\n",filename+1);
		}
		else
		{
			int access_mode;
			int file_attributes;

			Printf("file handle = 0x%04lx\n",vwv[0]);

			file_attributes = vwv[1];
			Printf("file attributes = 0x%04lx\n",file_attributes);

			if((file_attributes & 0x001f) == 0)
				Printf("                  SMB_FILE_ATTRIBUTE_NORMAL\n");

			if(file_attributes & 0x0001)
				Printf("                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

			if(file_attributes & 0x0002)
				Printf("                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

			if(file_attributes & 0x0004)
				Printf("                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

			if(file_attributes & 0x0008)
				Printf("                  SMB_FILE_ATTRIBUTE_VOLUME\n");

			if(file_attributes & 0x0010)
				Printf("                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

			if(file_attributes & 0x0020)
				Printf("                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

			Printf("last modified = 0x%04lx%04lx\n",vwv[3],vwv[2]);
			Printf("file size = %ld\n",(((int)vwv[5]) << 16) + vwv[4]);

			access_mode = vwv[6];
			Printf("access mode = 0x%04lx\n",access_mode);

			switch(access_mode & 0x0007)
			{
				case 0:

					Printf("              Open for reading\n");
					break;

				case 1:

					Printf("              Open for writing\n");
					break;

				case 2:

					Printf("              Open for reading and writing\n");
					break;

				case 3:

					Printf("              Open for execution\n");
					break;

				default:

					break;
			}

			switch((access_mode & 0x0070) >> 4)
			{
				case 0:

					Printf("              Compatibility mode\n");
					break;

				case 1:

					Printf("              Deny read/write/execute others (exclusive use requested)\n");
					break;

				case 2:

					Printf("              Deny write to others\n");
					break;

				case 3:

					Printf("              Deny read/execute to others\n");
					break;

				case 4:

					Printf("              Deny nothing to others\n");
					break;

				default:

					break;
			}

			switch((access_mode & 0x0700) >> 8)
			{
				case 0:

					Printf("              Unknown locality of reference\n");
					break;

				case 1:

					Printf("              Mainly sequential access\n");
					break;

				case 2:

					Printf("              Mainly random access\n");
					break;

				case 3:

					Printf("              Random access with some locality\n");
					break;

				default:

					break;
			}

			if(access_mode & 0x1000)
				Printf("              Perform caching on file\n");
			else
				Printf("              Do not cache the file\n");

			if(access_mode & 0x4000)
				Printf("              No read ahead or write behind is allowed on this file or device\n");
		}
	}
	else if (command == SMB_COM_CREATE)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];
			int file_attributes;
			
			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			file_attributes = vwv[0];
			Printf("file attributes = 0x%04lx\n",file_attributes);

			if((file_attributes & 0x001f) == 0)
				Printf("                  SMB_FILE_ATTRIBUTE_NORMAL\n");

			if(file_attributes & 0x0001)
				Printf("                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

			if(file_attributes & 0x0002)
				Printf("                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

			if(file_attributes & 0x0004)
				Printf("                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

			if(file_attributes & 0x0008)
				Printf("                  SMB_FILE_ATTRIBUTE_VOLUME\n");

			if(file_attributes & 0x0010)
				Printf("                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

			if(file_attributes & 0x0020)
				Printf("                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

			Printf("creation time = 0x%04l%04lx\n",vwv[2],vwv[1]);
			Printf("buffer format = %ld\n",filename[0]);
			Printf("file pathname = '%s'\n",filename+1);
		}
		else
		{
			Printf("file handle = 0x%04lx\n",vwv[0]);
		}
	}
	else if (command == SMB_COM_CLOSE)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			Printf("file handle = 0x%04lx\n",vwv[0]);
			Printf("last time modified = 0x%04lx%04lx\n",vwv[2],vwv[1]);
		}
	}
	else if (command == SMB_COM_DELETE)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];
			int search_attributes;
			
			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			search_attributes = vwv[0];
			Printf("search attributes = 0x%04lx\n",search_attributes);

			if(search_attributes & 0x0100)
				Printf("                   SMB_SEARCH_ATTRIBUTE_READONLY\n");

			if(search_attributes & 0x0200)
				Printf("                   SMB_SEARCH_ATTRIBUTE_HIDDEN\n");

			if(search_attributes & 0x0400)
				Printf("                   SMB_SEARCH_ATTRIBUTE_SYSTEM\n");

			if(search_attributes & 0x1000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_DIRECTORY\n");

			if(search_attributes & 0x2000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_ARCHIVE\n");

			Printf("buffer format = %ld\n",filename[0]);
			Printf("file name = '%s'\n",filename+1);
		}
	}
	else if (command == SMB_COM_RENAME)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			int search_attributes;
			const char * old_file_name;
			const char * new_file_name;
			int len;
			
			search_attributes = vwv[0];
			Printf("search attributes = 0x%04lx\n",search_attributes);

			if(search_attributes & 0x0100)
				Printf("                   SMB_SEARCH_ATTRIBUTE_READONLY\n");

			if(search_attributes & 0x0200)
				Printf("                   SMB_SEARCH_ATTRIBUTE_HIDDEN\n");

			if(search_attributes & 0x0400)
				Printf("                   SMB_SEARCH_ATTRIBUTE_SYSTEM\n");

			if(search_attributes & 0x1000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_DIRECTORY\n");

			if(search_attributes & 0x2000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_ARCHIVE\n");

			old_file_name = data;
			len = strlen(old_file_name);

			new_file_name = &old_file_name[len+1];

			Printf("buffer format 1 = %ld\n",old_file_name[0]);
			Printf("old file name = '%s'\n",old_file_name+1);

			Printf("buffer format 2 = %ld\n",new_file_name[0]);
			Printf("new file name = '%s'\n",new_file_name+1);
		}
	}
	else if (command == SMB_COM_QUERY_INFORMATION)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];
			
			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			Printf("buffer format = 0x%02lx\n",filename[0]);
			Printf("file pathname = '%s'\n",filename+1);
		}
		else
		{
			int file_attributes;

			file_attributes = vwv[0];
			Printf("file attributes = 0x%04lx\n",file_attributes);

			if((file_attributes & 0x001f) == 0)
				Printf("                  SMB_FILE_ATTRIBUTE_NORMAL\n");

			if(file_attributes & 0x0001)
				Printf("                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

			if(file_attributes & 0x0002)
				Printf("                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

			if(file_attributes & 0x0004)
				Printf("                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

			if(file_attributes & 0x0008)
				Printf("                  SMB_FILE_ATTRIBUTE_VOLUME\n");

			if(file_attributes & 0x0010)
				Printf("                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

			if(file_attributes & 0x0020)
				Printf("                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

			Printf("last write time = 0x%04lx%04lx\n",vwv[2],vwv[1]);
			Printf("file size = %ld\n",(((int)vwv[4]) << 16) + vwv[3]);
		}
	}
	else if (command == SMB_COM_SET_INFORMATION)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char filename[256];
			int file_attributes;
			
			if(num_data_bytes > 255)
				num_data_bytes = 255;
			
			memmove(filename,data,num_data_bytes);
			filename[num_data_bytes] = '\0';
			
			file_attributes = vwv[0];
			Printf("file attributes = 0x%04lx\n",file_attributes);

			if((file_attributes & 0x001f) == 0)
				Printf("                  SMB_FILE_ATTRIBUTE_NORMAL\n");

			if(file_attributes & 0x0001)
				Printf("                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

			if(file_attributes & 0x0002)
				Printf("                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

			if(file_attributes & 0x0004)
				Printf("                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

			if(file_attributes & 0x0008)
				Printf("                  SMB_FILE_ATTRIBUTE_VOLUME\n");

			if(file_attributes & 0x0010)
				Printf("                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

			if(file_attributes & 0x0020)
				Printf("                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

			Printf("creation time = 0x%04lx%04lx\n",vwv[2],vwv[1]);
			Printf("file pathname = '%s'\n",filename+1);
		}
	}
	else if (command == SMB_COM_READ)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			Printf("file handle = 0x%04lx\n",vwv[0]);
			Printf("count of bytes to read = %ld\n",vwv[1]);
			Printf("read offset in bytes = %ld\n",(((int)vwv[3]) << 16) + vwv[2]);
			Printf("estimate of remaining bytes to be read = %ld\n",vwv[4]);
		}
		else
		{
			unsigned char buffer_format;
			unsigned short count_of_bytes_read;
			int offset = 0;

			Printf("count of bytes returned = %ld\n",vwv[0]);

			buffer_format = next_data_byte(data,&offset);
			count_of_bytes_read = next_data_word(data,&offset);

			Printf("buffer format = %lu\n",buffer_format);
			Printf("count of bytes read = %lu\n",count_of_bytes_read);
		}
	}
	else if (command == SMB_COM_WRITE)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			unsigned char buffer_format;
			unsigned short data_length;
			int offset = 0;

			Printf("file handle = 0x%04lx\n",vwv[0]);
			Printf("count of bytes to write = %ld\n",vwv[1]);
			Printf("write offset in bytes = %ld\n",(((int)vwv[3]) << 16) + vwv[2]);
			Printf("estimate of remaining bytes to be written = %ld\n",vwv[4]);

			buffer_format = next_data_byte(data,&offset);
			data_length = next_data_word(data,&offset);

			Printf("buffer format = %lu\n",buffer_format);
			Printf("data length = %lu\n",data_length);
		}
		else
		{
			Printf("count of bytes written= %ld\n",vwv[0]);
		}
	}
	else if (command == SMB_COM_SEEK)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			int mode;

			Printf("file handle = 0x%04lx\n",vwv[0]);

			mode = vwv[1];
			Printf("mode = 0x%04lx\n",mode);

			switch(mode)
			{
				case 1:

					Printf("              Seek from the start of the file\n");
					break;

				case 2:

					Printf("              Seek from the current position\n");
					break;

				case 3:

					Printf("              Seek from the end of the file\n");
					break;
			}

			Printf("offset = %ld\n",(long)((((unsigned long)vwv[3]) << 16) | vwv[2]));
		}
		else
		{
			Printf("absolute position = %lu\n",(((unsigned long)vwv[1]) << 16) | vwv[0]);
		}
	}
	else if (command == SMB_COM_READ_RAW)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			Printf("file handle = 0x%04lx\n",vwv[0]);
			Printf("offset = %lu\n",(((unsigned long)vwv[2]) << 16) | vwv[1]);
			Printf("maximum count of bytes to return = %ld\n",vwv[3]);
			Printf("minimum count of byte to return = %ld\n",vwv[4]);
			Printf("timeout = %ld\n",(((int)vwv[6]) << 16) + vwv[5]);

			if(num_parameter_words == 0x0A)
				Printf("offset high = %lu\n",(((unsigned long)vwv[9]) << 16) | vwv[8]);
		}
	}
	else if (command == SMB_COM_WRITE_RAW)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			Printf("file handle = 0x%04lx\n",vwv[0]);
			Printf("cound of bytes = %lu\n",vwv[1]);
			Printf("offset = %lu\n",(((unsigned long)vwv[4]) << 16) | vwv[3]);
			Printf("timeout = %lu\n",(((unsigned long)vwv[6]) << 16) | vwv[5]);
			Printf("write mode = %ld\n",vwv[7]);

			if(vwv[7] & 0x0001)
				Printf("             Writethrough mode\n");

			if(vwv[7] & 0x0002)
				Printf("             Read bytes available\n");

			if(vwv[7] & 0x0004)
				Printf("             Named pipe raw\n");

			if(vwv[7] & 0x0008)
				Printf("             Named pipe start\n");

			Printf("data length = %lu\n",vwv[8]);
			Printf("data offset = %lu\n",vwv[9]);

			if(num_parameter_words == 0x0E)
				Printf("offset high = %lu\n",(((unsigned long)vwv[11]) << 16) | vwv[10]);
		}
		else
		{
			if(num_parameter_words > 0)
				Printf("number of bytes remaining to be written = %lu\n",vwv[0]);
		}
	}
	else if (command == SMB_COM_WRITE_COMPLETE)
	{
		if(smb_packet_source == smb_packet_to_consumer)
			Printf("total number of bytes written = %lu\n",vwv[0]);
	}
	else if (command == SMB_COM_SET_INFORMATION2)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			Printf("fid = %ld\n",vwv[0]);
			Printf("create date = %ld\n",vwv[1]);
			Printf("creation time = %ld\n",vwv[2]);
			Printf("last access date = %ld\n",vwv[3]);
			Printf("last access time = %ld\n",vwv[4]);
			Printf("last write date = %ld\n",vwv[5]);
			Printf("last write time = %ld\n",vwv[6]);
		}
	}
	else if (command == SMB_COM_QUERY_INFORMATION2)
	{
		if(smb_packet_source == smb_packet_to_consumer)
		{
			int file_attributes;

			Printf("fid = %ld\n",vwv[0]);
			Printf("create date = %ld\n",vwv[1]);
			Printf("creation time = %ld\n",vwv[2]);
			Printf("last access date = %ld\n",vwv[3]);
			Printf("last access time = %ld\n",vwv[4]);
			Printf("last write date = %ld\n",vwv[5]);
			Printf("last write time = %ld\n",vwv[6]);
			Printf("file data size = %lu\n",(((unsigned long)vwv[8]) << 16) | vwv[7]);
			Printf("file allocation size = %lu\n",(((unsigned long)vwv[10]) << 16) | vwv[9]);

			file_attributes = vwv[11];
			Printf("file attributes = 0x%04lx\n",file_attributes);

			if((file_attributes & 0x001f) == 0)
				Printf("                  SMB_FILE_ATTRIBUTE_NORMAL\n");

			if(file_attributes & 0x0001)
				Printf("                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

			if(file_attributes & 0x0002)
				Printf("                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

			if(file_attributes & 0x0004)
				Printf("                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

			if(file_attributes & 0x0008)
				Printf("                  SMB_FILE_ATTRIBUTE_VOLUME\n");

			if(file_attributes & 0x0010)
				Printf("                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

			if(file_attributes & 0x0020)
				Printf("                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");
		}
	}
	else if (command == SMB_COM_LOCKING_ANDX)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			int type_of_lock;
			int number_of_requested_unlocks;
			int number_of_requested_locks;
			int offset;
			int i;

			Printf("fid = %ld\n",vwv[0]);

			type_of_lock = vwv[1] & 0xff;
			Printf("type of lock = %ld\n",type_of_lock);

			if(type_of_lock & 0x01)
				Printf("                  SHARED_LOCK\n");
			else
				Printf("                  READ_WRITE_LOCK\n");

			if(type_of_lock & 0x02)
				Printf("                  OPLOCK_RELEASE\n");

			if(type_of_lock & 0x04)
				Printf("                  CHANGE_LOCK_TYPE\n");

			if(type_of_lock & 0x08)
				Printf("                  CANCEL_LOCK\n");

			if(type_of_lock & 0x10)
				Printf("                  LARGE_FILES\n");

			Printf("new oplock level = 0x%02lx\n",(vwv[1] >> 8) & 0xff);

			Printf("timeout = %lu\n",(((unsigned long)vwv[3]) << 16) | vwv[2]);

			number_of_requested_unlocks = vwv[4];

			Printf("number of requested unlocks = %ld\n",number_of_requested_unlocks);

			number_of_requested_locks = vwv[5];

			Printf("number of requested locks = %ld\n",number_of_requested_locks);

			offset = 0;

			for(i = 0 ; i < number_of_requested_unlocks ; i++)
			{
				Printf("unlock range[%ld] pid=%ld, byte offset = %lu, length in bytes = %lu\n",
					i,next_data_word(data,&offset),next_data_dword(data,&offset),next_data_dword(data,&offset));
			}

			for(i = 0 ; i < number_of_requested_locks ; i++)
			{
				Printf("lock range[%ld] pid=%ld, byte offset = %lu, length in bytes = %lu\n",
					i,next_data_word(data,&offset),next_data_dword(data,&offset),next_data_dword(data,&offset));
			}
		}
	}
	else if (command == SMB_COM_TRANSACTION2)
	{
		const unsigned short * setup_words;
		const char * subcommand_name;

		if(smb_packet_source == smb_packet_from_consumer)
		{
			int transaction_parameter_count;
			int transaction_parameter_offset;
			int transaction_data_count;
			int transaction_data_offset;
			int flags;
			int setup_count;
			int i;

			Printf("total parameter count = %ld\n",vwv[0]);
			Printf("total data count = %ld\n",vwv[1]);
			Printf("max parameter count = %ld\n",vwv[2]);
			Printf("max data count = %ld\n",vwv[3]);
			Printf("max setup count = %ld\n",vwv[4] & 0xff);

			flags = vwv[5];
			Printf("flags = 0x%04lx\n",flags);

			if(flags & 0x0001)
				Printf("        DISCONNECT_TID\n");

			if(flags & 0x0002)
				Printf("        NO_RESPONSE\n");

			Printf("timeout = %lu\n",(((unsigned long)vwv[7]) << 16) + vwv[6]);

			transaction_parameter_count = vwv[9];
			Printf("parameter count = %ld\n",transaction_parameter_count);

			transaction_parameter_offset = vwv[10];
			Printf("parameter offset = %ld (header parameter offset = %ld)\n",transaction_parameter_offset,header->parameter_offset);

			transaction_data_count = vwv[11];
			Printf("data count = %ld\n",transaction_data_count);

			transaction_data_offset = vwv[12];
			Printf("data offset = %ld (header data offset = %ld)\n",transaction_data_offset,header->data_offset);

			setup_count = vwv[13] & 0xff;
			Printf("setup count = %ld\n",setup_count);

			setup_words = &vwv[14];

			if(setup_count > 0)
			{
				last_smb_com_transaction_subcommand = setup_words[0];

				subcommand_name = get_smb_transaction2_subcommand_name(setup_words[0]);
				if(subcommand_name != NULL)
					Printf("subcommand = %s\n",subcommand_name);
				else
					Printf("subcommand = %ld\n",setup_words[0]);

				for(i = 0 ; i < setup_count ; i++)
					Printf("setup word [%ld] = 0x%04lx\n",i,setup_words[i]);
			}
			else
			{
				last_smb_com_transaction_subcommand = -1;
			}

			if(transaction_parameter_count > 0 && transaction_parameter_offset + transaction_parameter_count <= header->raw_packet_size)
			{
				const unsigned char * transaction_parameter_contents = (unsigned char *)&header->raw_packet[transaction_parameter_offset];
				struct line_buffer lb;

				Printf("transaction parameters =\n");

				print_smb_data(&lb,transaction_parameter_count,transaction_parameter_contents);
			}

			if(transaction_data_count > 0 && transaction_data_offset + transaction_data_count <= header->raw_packet_size)
			{
				const unsigned char * transaction_data_contents = (unsigned char *)&header->raw_packet[transaction_data_offset];
				struct line_buffer lb;

				Printf("transaction data =\n");

				print_smb_data(&lb,transaction_data_count,transaction_data_contents);
			}

			print_smb_transaction2_subcommand(last_smb_com_transaction_subcommand,smb_packet_source,
				transaction_parameter_count,(unsigned char *)&header->raw_packet[transaction_parameter_offset],
				transaction_data_count,(unsigned char *)&header->raw_packet[transaction_data_offset]);
		}
		else if (num_parameter_words > 0 || num_data_bytes > 0)
		{
			int transaction_parameter_count;
			int transaction_parameter_offset;
			int transaction_data_count;
			int transaction_data_offset;
			int setup_count;
			int i;

			Printf("total parameter count = %ld\n",vwv[0]);
			Printf("total data count = %ld\n",vwv[1]);

			transaction_parameter_count = vwv[3];
			Printf("parameter count = %ld\n",transaction_parameter_count);

			transaction_parameter_offset = vwv[4];
			Printf("parameter offset = %ld (header parameter offset = %ld)\n",transaction_parameter_offset,header->parameter_offset);

			Printf("parameter displacement = %ld\n",vwv[5]);

			transaction_data_count = vwv[6];
			Printf("data count = %ld\n",transaction_data_count);

			transaction_data_offset = vwv[7];
			Printf("data offset = %ld (header data offset = %ld)\n",transaction_data_offset,header->data_offset);

			setup_count = vwv[8] & 0xff;
			Printf("setup count = %ld\n",setup_count);

			setup_words = &vwv[9];

			if(setup_count > 0)
			{
				subcommand_name = get_smb_transaction2_subcommand_name(setup_words[0]);
				if(subcommand_name != NULL)
					Printf("subcommand = %s\n",subcommand_name);
				else
					Printf("subcommand = %ld\n",setup_words[0]);

				for(i = 0 ; i < setup_count ; i++)
					Printf("setup word [%ld] = 0x%04lx\n",i,setup_words[i]);
			}

			if(transaction_parameter_count > 0 && transaction_parameter_offset + transaction_parameter_count <= header->raw_packet_size)
			{
				const unsigned char * transaction_parameter_contents = (unsigned char *)&header->raw_packet[transaction_parameter_offset];
				struct line_buffer lb;

				Printf("transaction parameters =\n");

				print_smb_data(&lb,transaction_parameter_count,transaction_parameter_contents);
			}

			if(transaction_data_count > 0 && transaction_data_offset + transaction_data_count <= header->raw_packet_size)
			{
				const unsigned char * transaction_data_contents = (unsigned char *)&header->raw_packet[transaction_data_offset];
				struct line_buffer lb;

				Printf("transaction data =\n");

				print_smb_data(&lb,transaction_data_count,transaction_data_contents);
			}

			print_smb_transaction2_subcommand(last_smb_com_transaction_subcommand,smb_packet_source,
				transaction_parameter_count,(unsigned char *)&header->raw_packet[transaction_parameter_offset],
				transaction_data_count,(unsigned char *)&header->raw_packet[transaction_data_offset]);
		}
	}
	else if (command == SMB_COM_TREE_CONNECT)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			const char * path;
			const char * password;
			const char * service;
			int len;

			path = (char *)data;
			len = strlen(path);

			password = &path[len+1];
			len = strlen(password);

			service = &password[len+1];

			Printf("buffer format 1 = %ld\n",path[0]);
			Printf("path = '%s'\n",path+1);
			Printf("buffer format 2 = %ld\n",password[0]);
			Printf("password = '%s'\n",password+1);
			Printf("buffer format 3 = %ld\n",service[0]);
			Printf("service = '%s'\n",service+1);
		}
		else
		{
			Printf("max buffer size = %ld\n",vwv[0]);
			Printf("tid = %ld\n",vwv[1]);
		}
	}
	else if (command == SMB_COM_NEGOTIATE)
	{
		if(smb_packet_source == smb_packet_from_consumer)
		{
			char args[1024];
			const char * dialect;
			int dialect_index;
			int len;
			
			if(num_data_bytes > 1023)
				num_data_bytes = 1023;
			
			memmove(args,data,num_data_bytes);
			args[num_data_bytes] = '\0';
			
			dialect = args;
			dialect_index = 0;
			
			while(dialect < &args[num_data_bytes])
			{
				Printf("dialect[%ld] = '%s'\n",dialect_index++,&dialect[1]);
				
				len = strlen(&dialect[1]);
				
				dialect = &dialect[1+len+1];
			}
		}
		else
		{
			/* Assuming that the data returned is for
			 * the "NT LAN MANAGER" dialect.
			 */
			if(num_parameter_words == 0x11)
			{
				int offset = 0;
				int challenge_length;
				int security_mode;
				unsigned long capabilities;
				struct line_buffer lb;
				int unicode_char;
				int output_offset;

				Printf("dialect index = %ld\n",next_data_word(parameters,&offset));

				security_mode = next_data_byte(parameters,&offset);
				Printf("security mode = %ld\n",security_mode);

				if(security_mode & 0x01)
					Printf("                NEGOTIATE_USER_SECURITY\n");

				if(security_mode & 0x02)
					Printf("                NEGOTIATE_ENCRYPT_PASSWORDS\n");

				if(security_mode & 0x04)
					Printf("                NEGOTIATE_SECURITY_SIGNATURES_ENABLE\n");

				if(security_mode & 0x08)
					Printf("                NEGOTIATE_SECURITY_SIGNATURES_REQUIRED\n");

				if(security_mode & 0xF0)
					Printf("                Reserved = 0x%lx\n",security_mode >> 4);

				Printf("max mpx count = %ld\n",next_data_word(parameters,&offset));
				Printf("max number cvs = %ld\n",next_data_word(parameters,&offset));
				Printf("max buffer size = %ld\n",next_data_dword(parameters,&offset));
				Printf("max raw size = %ld\n",next_data_dword(parameters,&offset));
				Printf("session key = %ld\n",next_data_dword(parameters,&offset));

				capabilities = next_data_dword(parameters,&offset);
				Printf("capabilities = 0x%08lx\n",capabilities);

				if(capabilities & 0x00000001)
					Printf("               CAP_RAW_MODE\n");

				if(capabilities & 0x00000002)
					Printf("               CAP_MPX_MODE\n");

				if(capabilities & 0x00000004)
					Printf("               CAP_UNICODE\n");

				if(capabilities & 0x00000008)
					Printf("               CAP_LARGE_FILES\n");

				if(capabilities & 0x00000010)
					Printf("               CAP_NT_SMBS\n");

				if(capabilities & 0x00000020)
					Printf("               CAP_RPC_REMOTE_APIS\n");

				if(capabilities & 0x00000040)
					Printf("               CAP_STATUS32\n");

				if(capabilities & 0x00000080)
					Printf("               CAP_LEVEL_II_OPLOCKS\n");

				if(capabilities & 0x00000100)
					Printf("               CAP_LOCK_AND_READ\n");

				if(capabilities & 0x00000200)
					Printf("               CAP_NT_FIND\n");

				if(capabilities & 0x00000400)
					Printf("               CAP_BULK_TRANSFER\n");

				if(capabilities & 0x00000800)
					Printf("               CAP_COMPRESSED_DATA\n");

				if(capabilities & 0x00001000)
					Printf("               CAP_DFS\n");

				if(capabilities & 0x00002000)
					Printf("               CAP_QUADWORD_ALIGNED\n");

				if(capabilities & 0x00004000)
					Printf("               CAP_LARGE_READX\n");

				Printf("system time = 0x%08lx%08lx\n",next_data_dword(parameters,&offset),next_data_dword(parameters,&offset));
				Printf("server time zone = %ld\n",next_data_word(parameters,&offset));

				challenge_length = next_data_byte(parameters,&offset);
				Printf("challenge length = %ld\n",challenge_length);

				if(challenge_length > 0)
				{
					if(challenge_length == 8)
					{
						Printf("challenge = %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02lx\n",
							data[0],data[1],data[2],data[3],
							data[4],data[5],data[6],data[7]);
					}
				}

				init_line_buffer(&lb);

				offset = challenge_length;
				output_offset = 0;

				while(offset < num_data_bytes)
				{
					unicode_char = next_data_word(data,&offset);
					if(unicode_char == 0)
						break;

					if(' ' <= unicode_char && unicode_char < 127)
					{
						char c = unicode_char;

						copy_string_to_line_buffer(&lb,&c,1,output_offset);
						output_offset++;
					}
					else
					{
						char code_string[40];

						SPrintf(code_string,"<%02lx%02ld>",unicode_char >> 8,unicode_char & 0xff);

						copy_string_to_line_buffer(&lb,code_string,strlen(code_string),output_offset);
						output_offset += strlen(code_string);
					}
				}
				
				Printf("Domain name = '%s'\n",lb.line);
			}
			else
			{
				Printf("dialect index = %ld\n",vwv[0]);
			}
		}
	}
	else if (command == SMB_COM_SESSION_SETUP_ANDX)
	{
		char args[1024];
		char * args_end;
		int len;
		const char * oem_password = "";
		const char * unicode_password = "";
		const char * account_name = "";
		const char * primary_domain = "";
		const char * native_os = "";
		const char * native_lan_man = "";
		
		if(num_data_bytes > 1023)
			num_data_bytes = 1023;
		
		memmove(args,data,num_data_bytes);
		args[num_data_bytes] = '\0';

		args_end = &args[num_data_bytes];

		if(smb_packet_source == smb_packet_from_consumer)
		{
			int oem_password_length;
			int unicode_password_length;
			unsigned long capabilities;

			Printf("consumer's maximum buffer size = %ld\n",vwv[0]);
			Printf("actual maximum multiplexed pending requests = %ld\n",vwv[1]);
			Printf("vc number = %ld\n",vwv[2]);
			Printf("session key = 0x%04lx%04lx\n",vwv[4],vwv[3]);

			oem_password_length = vwv[5];
			Printf("oem password length = %ld\n",oem_password_length);

			unicode_password_length = vwv[6];
			Printf("unicode password length = %ld\n",unicode_password_length);

			capabilities = (((unsigned long)vwv[10]) << 16) + vwv[9];

			Printf("capabilities = 0x%08lx\n",capabilities);
			
			if(capabilities & 0x00000001)
				Printf("               CAP_RAW_MODE\n");

			if(capabilities & 0x00000002)
				Printf("               CAP_MPX_MODE\n");

			if(capabilities & 0x00000004)
				Printf("               CAP_UNICODE\n");

			if(capabilities & 0x00000008)
				Printf("               CAP_LARGE_FILES\n");

			if(capabilities & 0x00000010)
				Printf("               CAP_NT_SMBS\n");

			if(capabilities & 0x00000020)
				Printf("               CAP_RPC_REMOTE_APIS\n");

			if(capabilities & 0x00000040)
				Printf("               CAP_STATUS32\n");

			if(capabilities & 0x00000080)
				Printf("               CAP_LEVEL_II_OPLOCKS\n");

			if(capabilities & 0x00000100)
				Printf("               CAP_LOCK_AND_READ\n");

			if(capabilities & 0x00000200)
				Printf("               CAP_NT_FIND\n");

			if(capabilities & 0x00000400)
				Printf("               CAP_BULK_TRANSFER\n");

			if(capabilities & 0x00000800)
				Printf("               CAP_COMPRESSED_DATA\n");

			if(capabilities & 0x00001000)
				Printf("               CAP_DFS\n");

			if(capabilities & 0x00002000)
				Printf("               CAP_QUADWORD_ALIGNED\n");

			if(capabilities & 0x00004000)
				Printf("               CAP_LARGE_READX\n");

			if(num_data_bytes > 0)
			{
				oem_password = args;
				
				len = oem_password_length;
				
				unicode_password = &oem_password[len];
				if(unicode_password < args_end)
				{
					len = unicode_password_length;

					/* There could be a padding byte here which
					 * aligns the account name to a word
					 * boundary.
					 */
					if((header->flags2 & SMB_FLAGS2_UNICODE_STRINGS) && (len % 2) == 1)
						len++;

					account_name = &unicode_password[len];
					if(account_name < args_end)
					{
						len = strlen(account_name);
						
						/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
						primary_domain = &account_name[len+1];
						if(primary_domain < args_end)
						{
							len = strlen(primary_domain);
						
							/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
							native_os = &primary_domain[len+1];
							if(native_os < args_end)
							{
								len = strlen(native_os);
						
								/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
								native_lan_man = &native_os[len+1];
							}
						}
					}
				}
			}
			
			Printf("account name = '%s'\n",account_name);
			Printf("primary domain = '%s'\n",primary_domain);
			Printf("native os = '%s'\n",native_os);
			Printf("native lan man = '%s'\n",native_lan_man);
		}
		else
		{
			int request_mode;

			request_mode = vwv[0];
			Printf("request mode = 0x%04lx\n",request_mode);

			if(request_mode & 0x0001)
				Printf("               SMB_SETUP_GUEST\n");

			if(request_mode & 0x0002)
				Printf("               SMB_SETUP_USE_LANMAN_KEY\n");

			if(num_data_bytes > 0)
			{
				/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
				native_os = args;
				
				len = strlen(native_os);
				
				/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
				native_lan_man = &native_os[len+1];
				if(native_lan_man < args_end)
				{
					len = strlen(native_lan_man);

					/* ZZZ could be Unicode if SMB_FLAGS2_UNICODE_STRINGS is set. */
					primary_domain = &native_lan_man[len+1];
				}
			}
			
			Printf("native os = '%s'\n",native_os);
			Printf("native lan man = '%s'\n",native_lan_man);
			Printf("primary domain = '%s'\n",primary_domain);
		}
	}
	else if (command == SMB_COM_TREE_CONNECT_ANDX)
	{
		char args[1024];

		if(num_data_bytes > 1023)
			num_data_bytes = 1023;
			
		memmove(args,data,num_data_bytes);
		args[num_data_bytes] = '\0';
			
		if(smb_packet_source == smb_packet_from_consumer)
		{
			const char * path;
			const char * password;
			const char * dev_name;
			int len;
			int flags;
			int password_length;

			flags = vwv[0];
			Printf("flags = 0x%04lx\n",flags);

			if(flags & 0x0001)
				Printf("        TREE_CONNECT_ANDX_DISCONNECT_TID\n");

			password_length = vwv[1];

			Printf("password length = %ld\n",password_length);

			password = args;
			len = password_length;
			
			/* There could be a padding byte here which
			 * aligns the account name to a word
			 * boundary.
			 */
			if((header->flags2 & SMB_FLAGS2_UNICODE_STRINGS) && (len % 2) == 1)
				len++;

			/* ZZZ could be a Unicode string. */
			path = &password[len];
			len = (int)strlen(path)+1;

			dev_name = &path[len];
			
			Printf("path = '%s'\n",path);
			// Printf("password = '%s'\n",password);
			Printf("dev name = '%s'\n",dev_name);
		}
		else
		{
			int len;
			const char * service;
			const char * native_file_system;

			service = args;
			len = strlen(service)+1;

			/* ZZZ this could be Unicode text. */
			native_file_system = &service[len];

			Printf("service = '%s'\n",service);
			Printf("native file system = '%s'\n",native_file_system);
		}
	}
	else if (command == SMB_COM_QUERY_INFORMATION_DISK)
	{
		if(smb_packet_source == smb_packet_to_consumer)
		{
			Printf("allocation units/server = %ld\n",vwv[0]);
			Printf("blocks/allocation unit = %ld\n",vwv[1]);
			Printf("block size (in bytes) = %ld\n",vwv[2]);
			Printf("free allocation units = %ld\n",vwv[3]);
		}
	}
	else if (command == SMB_COM_SEARCH)
	{
		if(smb_packet_source == smb_packet_to_consumer)
		{
			int search_attributes;
			const char * file_name;
			const unsigned char * resume_key_data;
			int resume_key_length;
			int len;
			int offset;

			Printf("max count = %ld\n",vwv[0]);

			search_attributes = vwv[1];
			Printf("search attributes = 0x%04lx\n",search_attributes);

			if(search_attributes & 0x0100)
				Printf("                   SMB_SEARCH_ATTRIBUTE_READONLY\n");

			if(search_attributes & 0x0200)
				Printf("                   SMB_SEARCH_ATTRIBUTE_HIDDEN\n");

			if(search_attributes & 0x0400)
				Printf("                   SMB_SEARCH_ATTRIBUTE_SYSTEM\n");

			if(search_attributes & 0x1000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_DIRECTORY\n");

			if(search_attributes & 0x2000)
				Printf("                   SMB_SEARCH_ATTRIBUTE_ARCHIVE\n");

			file_name = (char *)data;
			len = strlen(file_name);

			Printf("buffer format = %ld\n",file_name[0]);
			Printf("file name = '%s'\n",file_name+1);

			resume_key_data = (unsigned char *)&file_name[len+1];
			offset = 0;

			resume_key_length = next_data_word(resume_key_data,&offset);

			Printf("resume key length = %ld\n",resume_key_length);

			if(resume_key_length == 21)
			{
				unsigned char reserved;
				const unsigned char * server_state;
				const unsigned char * client_state;

				reserved = next_data_byte(resume_key_data,&offset);
				server_state = next_data_bytes(resume_key_data,16,&offset);
				client_state = next_data_bytes(resume_key_data,4,&offset);

				Printf("resume key reserved = %02lx\n",reserved);

				Printf("resume key server state = ");

				for(i = 0 ; i < 16 ; i++)
					Printf("%02lx",server_state[i]);

				Printf("\n");

				Printf("resume key client state = ");

				for(i = 0 ; i < 4 ; i++)
					Printf("%02lx",client_state[i]);

				Printf("\n");
			}
		}
		else
		{
			unsigned char reserved;
			const unsigned char * server_state;
			const unsigned char * client_state;

			int count;
			int offset;
			int buffer_format;
			int data_length;
			int i,j;
			int file_attributes;
			const char * file_name;

			count = vwv[0];

			Printf("count = %ld\n",count);

			offset = 0;

			buffer_format = next_data_byte(data,&offset);

			Printf("buffer format = %ld\n",buffer_format);

			data_length = next_data_word(data,&offset);

			Printf("data length = %ld\n",data_length);

			for(j = 0 ; j < count ; j++)
			{
				Printf("directory entry [%ld]:\n",j);

				reserved = next_data_byte(data,&offset);
				server_state = next_data_bytes(data,16,&offset);
				client_state = next_data_bytes(data,4,&offset);

				Printf("\tresume key reserved = %02lx\n",reserved);

				Printf("\tresume key server state = ");

				for(i = 0 ; i < 16 ; i++)
					Printf("%02lx",server_state[i]);

				Printf("\n");

				Printf("\tresume key client state = ");

				for(i = 0 ; i < 4 ; i++)
					Printf("%02lx",client_state[i]);

				Printf("\n");

				file_attributes = next_data_byte(data,&offset);

				Printf("file attributes = 0x%04lx\n",file_attributes);

				if((file_attributes & 0x001f) == 0)
					Printf("\t                  SMB_FILE_ATTRIBUTE_NORMAL\n");

				if(file_attributes & 0x0001)
					Printf("\t                  SMB_FILE_ATTRIBUTE_READ_ONLY\n");

				if(file_attributes & 0x0002)
					Printf("\t                  SMB_FILE_ATTRIBUTE_HIDDEN\n");

				if(file_attributes & 0x0004)
					Printf("\t                  SMB_FILE_ATTRIBUTE_SYSTEM\n");

				if(file_attributes & 0x0008)
					Printf("\t                  SMB_FILE_ATTRIBUTE_VOLUME\n");

				if(file_attributes & 0x0010)
					Printf("\t                  SMB_FILE_ATTRIBUTE_DIRECTORY\n");

				if(file_attributes & 0x0020)
					Printf("\t                  SMB_FILE_ATTRIBUTE_ARCHIVE\n");

				Printf("\tlast write time = %ld\n",next_data_word(data,&offset));
				Printf("\tlast write date = %ld\n",next_data_word(data,&offset));
				Printf("\tfile size = %lu\n",next_data_dword(data,&offset));

				file_name = (const char *)next_data_bytes(data,13,&offset);

				Printf("\tfile name = '%s'\n",file_name);
			}
		}
	}
}

/*****************************************************************************/

static void
print_smb_parameters(int num_parameter_words,const unsigned char *parameters)
{
	if(num_parameter_words > 0)
	{
		int word_value;
		int i,j;

		for(i = j = 0 ; i < num_parameter_words ; i++, j++)
		{
			word_value = parameters[j] + (((int)parameters[j+1]) << 8);

			Printf("                  %04lx: %04lx (bytes: %02lx%02lx)\n",i,word_value,parameters[j],parameters[j+1]);
		}
	}
}

/*****************************************************************************/

static void
print_smb_header(const struct smb_header * header,int header_length,const unsigned char *packet,int packet_size,enum smb_packet_source_t smb_packet_source,int max_buffer_size)
{
	enum errdos_t
	{
		errdos_badfunc=1,
		errdos_badfile=2,
		errdos_badpath=3,
		errdos_nofids=4,
		errdos_noaccess=5,
		errdos_badfid=6,
		errdos_badmcb=7,
		errdos_nomem=8,
		errdos_badmem=9,
		errdos_badenv=10,
		errdos_badformat=11,
		errdos_badaccess=12,
		errdos_baddata=13,
		errdos_baddrive=15,
		errdos_remcd=16,
		errdos_diffdevice=17,
		errdos_nofiles=18,
		errdos_badshare=32,
		errdos_lock=33,
		errdos_filexists=80,
		errdos_quota=512,
		errdos_notALink=513,
	};

	enum errsrv_t
	{
		errsrv_error=1,
		errsrv_badpw=2,
		errsrv_access=4,
		errsrv_invtid=5,
		errsrv_invnetname=6,
		errsrv_invdevice=7,
		errsrv_qfull=49,
		errsrv_qtoobig=50,
		errsrv_qeof=51,
		errsrv_invpfid=52,
		errsrv_smbcmd=64,
		errsrv_srverror=65,
		errsrv_badBID=66,
		errsrv_filespecs=67,
		errsrv_badLink=68,
		errsrv_badpermits=69,
		errsrv_badPID=70,
		errsrv_setattrmode=71,
		errsrv_paused=81,
		errsrv_msgoff=82,
		errsrv_noroom=83,
		errsrv_rmuns=87,
		errsrv_timeout=88,
		errsrv_noresource=89,
		errsrv_toomanyuids=90,
		errsrv_baduid=91,
		errsrv_usempx=250,
		errsrv_usestd=251,
		errsrv_contmpx=252,
		errsrv_badPassword=254,
		errsrv_notifyEnumDir=1024,
		errsrv_accountExpired=2239,
		errsrv_badClient=2240,
		errsrv_badLogonTime=2241,
		errsrv_passwordExpired=2242,
		errsrv_nosupport=65535,
	};

	enum errhrd_t
	{
		errhrd_nowrite=19,
		errhrd_badunit=20,
		errhrd_notready=21,
		errhrd_badcmd=22,
		errhrd_data=23,
		errhrd_badreq=24,
		errhrd_seek=25,
		errhrd_badmedia=26,
		errhrd_badsector=27,
		errhrd_nopaper=28,
		errhrd_write=29,
		errhrd_read=30,
		errhrd_general=31,
		errhrd_badshare=32,
		errhrd_lock=33,
		errhrd_wrongdisk=34,
		errhrd_FCBUnavail=35,
		errhrd_sharebufexc=36,
	};

	enum nt_status_t
	{
		nt_status_unsuccessful=1,
		nt_status_not_implemented=2,
		nt_status_invalid_info_class=3,
		nt_status_info_length_mismatch=4,
		nt_status_access_violation=5,
		nt_status_in_page_error=6,
		nt_status_pagefile_quota=7,
		nt_status_invalid_handle=8,
		nt_status_bad_initial_stack=9,
		nt_status_bad_initial_pc=10,
		nt_status_invalid_cid=11,
		nt_status_timer_not_canceled=12,
		nt_status_invalid_parameter=13,
		nt_status_no_such_device=14,
		nt_status_no_such_file=15,
		nt_status_invalid_device_request=16,
		nt_status_end_of_file=17,
		nt_status_wrong_volume=18,
		nt_status_no_media_in_device=19,
		nt_status_unrecognized_media=20,
		nt_status_nonexistent_sector=21,
		nt_status_more_processing_required=22,
		nt_status_no_memory=23,
		nt_status_conflicting_addresses=24,
		nt_status_not_mapped_view=25,
		nt_status_unable_to_free_vm=26,
		nt_status_unable_to_delete_section=27,
		nt_status_invalid_system_service=28,
		nt_status_illegal_instruction=29,
		nt_status_invalid_lock_sequence=30,
		nt_status_invalid_view_size=31,
		nt_status_invalid_file_for_section=32,
		nt_status_already_committed=33,
		nt_status_access_denied=34,
		nt_status_buffer_too_small=35,
		nt_status_object_type_mismatch=36,
		nt_status_noncontinuable_exception=37,
		nt_status_invalid_disposition=38,
		nt_status_unwind=39,
		nt_status_bad_stack=40,
		nt_status_invalid_unwind_target=41,
		nt_status_not_locked=42,
		nt_status_parity_error=43,
		nt_status_unable_to_decommit_vm=44,
		nt_status_not_committed=45,
		nt_status_invalid_port_attributes=46,
		nt_status_port_message_too_long=47,
		nt_status_invalid_parameter_mix=48,
		nt_status_invalid_quota_lower=49,
		nt_status_disk_corrupt_error=50,
		nt_status_object_name_invalid=51,
		nt_status_object_name_not_found=52,
		nt_status_object_name_collision=53,
		nt_status_handle_not_waitable=54,
		nt_status_port_disconnected=55,
		nt_status_device_already_attached=56,
		nt_status_object_path_invalid=57,
		nt_status_object_path_not_found=58,
		nt_status_object_path_syntax_bad=59,
		nt_status_data_overrun=60,
		nt_status_data_late_error=61,
		nt_status_data_error=62,
		nt_status_crc_error=63,
		nt_status_section_too_big=64,
		nt_status_port_connection_refused=65,
		nt_status_invalid_port_handle=66,
		nt_status_sharing_violation=67,
		nt_status_quota_exceeded=68,
		nt_status_invalid_page_protection=69,
		nt_status_mutant_not_owned=70,
		nt_status_semaphore_limit_exceeded=71,
		nt_status_port_already_set=72,
		nt_status_section_not_image=73,
		nt_status_suspend_count_exceeded=74,
		nt_status_thread_is_terminating=75,
		nt_status_bad_working_set_limit=76,
		nt_status_incompatible_file_map=77,
		nt_status_section_protection=78,
		nt_status_eas_not_supported=79,
		nt_status_ea_too_large=80,
		nt_status_nonexistent_ea_entry=81,
		nt_status_no_eas_on_file=82,
		nt_status_ea_corrupt_error=83,
		nt_status_file_lock_conflict=84,
		nt_status_lock_not_granted=85,
		nt_status_delete_pending=86,
		nt_status_ctl_file_not_supported=87,
		nt_status_unknown_revision=88,
		nt_status_revision_mismatch=89,
		nt_status_invalid_owner=90,
		nt_status_invalid_primary_group=91,
		nt_status_no_impersonation_token=92,
		nt_status_cant_disable_mandatory=93,
		nt_status_no_logon_servers=94,
		nt_status_no_such_logon_session=95,
		nt_status_no_such_privilege=96,
		nt_status_privilege_not_held=97,
		nt_status_invalid_account_name=98,
		nt_status_user_exists=99,
		nt_status_no_such_user=100,
		nt_status_group_exists=101,
		nt_status_no_such_group=102,
		nt_status_member_in_group=103,
		nt_status_member_not_in_group=104,
		nt_status_last_admin=105,
		nt_status_wrong_password=106,
		nt_status_ill_formed_password=107,
		nt_status_password_restriction=108,
		nt_status_logon_failure=109,
		nt_status_account_restriction=110,
		nt_status_invalid_logon_hours=111,
		nt_status_invalid_workstation=112,
		nt_status_password_expired=113,
		nt_status_account_disabled=114,
		nt_status_none_mapped=115,
		nt_status_too_many_luids_requested=116,
		nt_status_luids_exhausted=117,
		nt_status_invalid_sub_authority=118,
		nt_status_invalid_acl=119,
		nt_status_invalid_sid=120,
		nt_status_invalid_security_descr=121,
		nt_status_procedure_not_found=122,
		nt_status_invalid_image_format=123,
		nt_status_no_token=124,
		nt_status_bad_inheritance_acl=125,
		nt_status_range_not_locked=126,
		nt_status_disk_full=127,
		nt_status_server_disabled=128,
		nt_status_server_not_disabled=129,
		nt_status_too_many_guids_requested=130,
		nt_status_guids_exhausted=131,
		nt_status_invalid_id_authority=132,
		nt_status_agents_exhausted=133,
		nt_status_invalid_volume_label=134,
		nt_status_section_not_extended=135,
		nt_status_not_mapped_data=136,
		nt_status_resource_data_not_found=137,
		nt_status_resource_type_not_found=138,
		nt_status_resource_name_not_found=139,
		nt_status_array_bounds_exceeded=140,
		nt_status_float_denormal_operand=141,
		nt_status_float_divide_by_zero=142,
		nt_status_float_inexact_result=143,
		nt_status_float_invalid_operation=144,
		nt_status_float_overflow=145,
		nt_status_float_stack_check=146,
		nt_status_float_underflow=147,
		nt_status_integer_divide_by_zero=148,
		nt_status_integer_overflow=149,
		nt_status_privileged_instruction=150,
		nt_status_too_many_paging_files=151,
		nt_status_file_invalid=152,
		nt_status_allotted_space_exceeded=153,
		nt_status_insufficient_resources=154,
		nt_status_dfs_exit_path_found=155,
		nt_status_device_data_error=156,
		nt_status_device_not_connected=157,
		nt_status_device_power_failure=158,
		nt_status_free_vm_not_at_base=159,
		nt_status_memory_not_allocated=160,
		nt_status_working_set_quota=161,
		nt_status_media_write_protected=162,
		nt_status_device_not_ready=163,
		nt_status_invalid_group_attributes=164,
		nt_status_bad_impersonation_level=165,
		nt_status_cant_open_anonymous=166,
		nt_status_bad_validation_class=167,
		nt_status_bad_token_type=168,
		nt_status_bad_master_boot_record=169,
		nt_status_instruction_misalignment=170,
		nt_status_instance_not_available=171,
		nt_status_pipe_not_available=172,
		nt_status_invalid_pipe_state=173,
		nt_status_pipe_busy=174,
		nt_status_illegal_function=175,
		nt_status_pipe_disconnected=176,
		nt_status_pipe_closing=177,
		nt_status_pipe_connected=178,
		nt_status_pipe_listening=179,
		nt_status_invalid_read_mode=180,
		nt_status_io_timeout=181,
		nt_status_file_forced_closed=182,
		nt_status_profiling_not_started=183,
		nt_status_profiling_not_stopped=184,
		nt_status_could_not_interpret=185,
		nt_status_file_is_a_directory=186,
		nt_status_not_supported=187,
		nt_status_remote_not_listening=188,
		nt_status_duplicate_name=189,
		nt_status_bad_network_path=190,
		nt_status_network_busy=191,
		nt_status_device_does_not_exist=192,
		nt_status_too_many_commands=193,
		nt_status_adapter_hardware_error=194,
		nt_status_invalid_network_response=195,
		nt_status_unexpected_network_error=196,
		nt_status_bad_remote_adapter=197,
		nt_status_print_queue_full=198,
		nt_status_no_spool_space=199,
		nt_status_print_cancelled=200,
		nt_status_network_name_deleted=201,
		nt_status_network_access_denied=202,
		nt_status_bad_device_type=203,
		nt_status_bad_network_name=204,
		nt_status_too_many_names=205,
		nt_status_too_many_sessions=206,
		nt_status_sharing_paused=207,
		nt_status_request_not_accepted=208,
		nt_status_redirector_paused=209,
		nt_status_net_write_fault=210,
		nt_status_profiling_at_limit=211,
		nt_status_not_same_device=212,
		nt_status_file_renamed=213,
		nt_status_virtual_circuit_closed=214,
		nt_status_no_security_on_object=215,
		nt_status_cant_wait=216,
		nt_status_pipe_empty=217,
		nt_status_cant_access_domain_info=218,
		nt_status_cant_terminate_self=219,
		nt_status_invalid_server_state=220,
		nt_status_invalid_domain_state=221,
		nt_status_invalid_domain_role=222,
		nt_status_no_such_domain=223,
		nt_status_domain_exists=224,
		nt_status_domain_limit_exceeded=225,
		nt_status_oplock_not_granted=226,
		nt_status_invalid_oplock_protocol=227,
		nt_status_internal_db_corruption=228,
		nt_status_internal_error=229,
		nt_status_generic_not_mapped=230,
		nt_status_bad_descriptor_format=231,
		nt_status_invalid_user_buffer=232,
		nt_status_unexpected_io_error=233,
		nt_status_unexpected_mm_create_err=234,
		nt_status_unexpected_mm_map_error=235,
		nt_status_unexpected_mm_extend_err=236,
		nt_status_not_logon_process=237,
		nt_status_logon_session_exists=238,
		nt_status_invalid_parameter_1=239,
		nt_status_invalid_parameter_2=240,
		nt_status_invalid_parameter_3=241,
		nt_status_invalid_parameter_4=242,
		nt_status_invalid_parameter_5=243,
		nt_status_invalid_parameter_6=244,
		nt_status_invalid_parameter_7=245,
		nt_status_invalid_parameter_8=246,
		nt_status_invalid_parameter_9=247,
		nt_status_invalid_parameter_10=248,
		nt_status_invalid_parameter_11=249,
		nt_status_invalid_parameter_12=250,
		nt_status_redirector_not_started=251,
		nt_status_redirector_started=252,
		nt_status_stack_overflow=253,
		nt_status_no_such_package=254,
		nt_status_bad_function_table=255,
		nt_status_directory_not_empty=257,
		nt_status_file_corrupt_error=258,
		nt_status_not_a_directory=259,
		nt_status_bad_logon_session_state=260,
		nt_status_logon_session_collision=261,
		nt_status_name_too_long=262,
		nt_status_files_open=263,
		nt_status_connection_in_use=264,
		nt_status_message_not_found=265,
		nt_status_process_is_terminating=266,
		nt_status_invalid_logon_type=267,
		nt_status_no_guid_translation=268,
		nt_status_cannot_impersonate=269,
		nt_status_image_already_loaded=270,
		nt_status_abios_not_present=271,
		nt_status_abios_lid_not_exist=272,
		nt_status_abios_lid_already_owned=273,
		nt_status_abios_not_lid_owner=274,
		nt_status_abios_invalid_command=275,
		nt_status_abios_invalid_lid=276,
		nt_status_abios_selector_not_available=277,
		nt_status_abios_invalid_selector=278,
		nt_status_no_ldt=279,
		nt_status_invalid_ldt_size=280,
		nt_status_invalid_ldt_offset=281,
		nt_status_invalid_ldt_descriptor=282,
		nt_status_invalid_image_ne_format=283,
		nt_status_rxact_invalid_state=284,
		nt_status_rxact_commit_failure=285,
		nt_status_mapped_file_size_zero=286,
		nt_status_too_many_opened_files=287,
		nt_status_cancelled=288,
		nt_status_cannot_delete=289,
		nt_status_invalid_computer_name=290,
		nt_status_file_deleted=291,
		nt_status_special_account=292,
		nt_status_special_group=293,
		nt_status_special_user=294,
		nt_status_members_primary_group=295,
		nt_status_file_closed=296,
		nt_status_too_many_threads=297,
		nt_status_thread_not_in_process=298,
		nt_status_token_already_in_use=299,
		nt_status_pagefile_quota_exceeded=300,
		nt_status_commitment_limit=301,
		nt_status_invalid_image_le_format=302,
		nt_status_invalid_image_not_mz=303,
		nt_status_invalid_image_protect=304,
		nt_status_invalid_image_win_16=305,
		nt_status_logon_server_conflict=306,
		nt_status_time_difference_at_dc=307,
		nt_status_synchronization_required=308,
		nt_status_dll_not_found=309,
		nt_status_open_failed=310,
		nt_status_io_privilege_failed=311,
		nt_status_ordinal_not_found=312,
		nt_status_entrypoint_not_found=313,
		nt_status_control_c_exit=314,
		nt_status_local_disconnect=315,
		nt_status_remote_disconnect=316,
		nt_status_remote_resources=317,
		nt_status_link_failed=318,
		nt_status_link_timeout=319,
		nt_status_invalid_connection=320,
		nt_status_invalid_address=321,
		nt_status_dll_init_failed=322,
		nt_status_missing_systemfile=323,
		nt_status_unhandled_exception=324,
		nt_status_app_init_failure=325,
		nt_status_pagefile_create_failed=326,
		nt_status_no_pagefile=327,
		nt_status_invalid_level=328,
		nt_status_wrong_password_core=329,
		nt_status_illegal_float_context=330,
		nt_status_pipe_broken=331,
		nt_status_registry_corrupt=332,
		nt_status_registry_io_failed=333,
		nt_status_no_event_pair=334,
		nt_status_unrecognized_volume=335,
		nt_status_serial_no_device_inited=336,
		nt_status_no_such_alias=337,
		nt_status_member_not_in_alias=338,
		nt_status_member_in_alias=339,
		nt_status_alias_exists=340,
		nt_status_logon_not_granted=341,
		nt_status_too_many_secrets=342,
		nt_status_secret_too_long=343,
		nt_status_internal_db_error=344,
		nt_status_fullscreen_mode=345,
		nt_status_too_many_context_ids=346,
		nt_status_logon_type_not_granted=347,
		nt_status_not_registry_file=348,
		nt_status_nt_cross_encryption_required=349,
		nt_status_domain_ctrlr_config_error=350,
		nt_status_ft_missing_member=351,
		nt_status_ill_formed_service_entry=352,
		nt_status_illegal_character=353,
		nt_status_unmappable_character=354,
		nt_status_undefined_character=355,
		nt_status_floppy_volume=356,
		nt_status_floppy_id_mark_not_found=357,
		nt_status_floppy_wrong_cylinder=358,
		nt_status_floppy_unknown_error=359,
		nt_status_floppy_bad_registers=360,
		nt_status_disk_recalibrate_failed=361,
		nt_status_disk_operation_failed=362,
		nt_status_disk_reset_failed=363,
		nt_status_shared_irq_busy=364,
		nt_status_ft_orphaning=365,
		nt_status_partition_failure=370,
		nt_status_invalid_block_length=371,
		nt_status_device_not_partitioned=372,
		nt_status_unable_to_lock_media=373,
		nt_status_unable_to_unload_media=374,
		nt_status_eom_overflow=375,
		nt_status_no_media=376,
		nt_status_no_such_member=378,
		nt_status_invalid_member=379,
		nt_status_key_deleted=380,
		nt_status_no_log_space=381,
		nt_status_too_many_sids=382,
		nt_status_lm_cross_encryption_required=383,
		nt_status_key_has_children=384,
		nt_status_child_must_be_volatile=385,
		nt_status_device_configuration_error=386,
		nt_status_driver_internal_error=387,
		nt_status_invalid_device_state=388,
		nt_status_io_device_error=389,
		nt_status_device_protocol_error=390,
		nt_status_backup_controller=391,
		nt_status_log_file_full=392,
		nt_status_too_late=393,
		nt_status_no_trust_lsa_secret=394,
		nt_status_no_trust_sam_account=395,
		nt_status_trusted_domain_failure=396,
		nt_status_trusted_relationship_failure=397,
		nt_status_eventlog_file_corrupt=398,
		nt_status_eventlog_cant_start=399,
		nt_status_trust_failure=400,
		nt_status_mutant_limit_exceeded=401,
		nt_status_netlogon_not_started=402,
		nt_status_account_expired=403,
		nt_status_possible_deadlock=404,
		nt_status_network_credential_conflict=405,
		nt_status_remote_session_limit=406,
		nt_status_eventlog_file_changed=407,
		nt_status_nologon_interdomain_trust_account=408,
		nt_status_nologon_workstation_trust_account=409,
		nt_status_nologon_server_trust_account=410,
		nt_status_domain_trust_inconsistent=411,
		nt_status_fs_driver_required=412,
		nt_status_no_user_session_key=514,
		nt_status_user_session_deleted=515,
		nt_status_resource_lang_not_found=516,
		nt_status_insuff_server_resources=517,
		nt_status_invalid_buffer_size=518,
		nt_status_invalid_address_component=519,
		nt_status_invalid_address_wildcard=520,
		nt_status_too_many_addresses=521,
		nt_status_address_already_exists=522,
		nt_status_address_closed=523,
		nt_status_connection_disconnected=524,
		nt_status_connection_reset=525,
		nt_status_too_many_nodes=526,
		nt_status_transaction_aborted=527,
		nt_status_transaction_timed_out=528,
		nt_status_transaction_no_release=529,
		nt_status_transaction_no_match=530,
		nt_status_transaction_responded=531,
		nt_status_transaction_invalid_id=532,
		nt_status_transaction_invalid_type=533,
		nt_status_not_server_session=534,
		nt_status_not_client_session=535,
		nt_status_cannot_load_registry_file=536,
		nt_status_debug_attach_failed=537,
		nt_status_system_process_terminated=538,
		nt_status_data_not_accepted=539,
		nt_status_no_browser_servers_found=540,
		nt_status_vdm_hard_error=541,
		nt_status_driver_cancel_timeout=542,
		nt_status_reply_message_mismatch=543,
		nt_status_mapped_alignment=544,
		nt_status_image_checksum_mismatch=545,
		nt_status_lost_writebehind_data=546,
		nt_status_client_server_parameters_invalid=547,
		nt_status_password_must_change=548,
		nt_status_not_found=549,
		nt_status_not_tiny_stream=550,
		nt_status_recovery_failure=551,
		nt_status_stack_overflow_read=552,
		nt_status_fail_check=553,
		nt_status_duplicate_objectid=554,
		nt_status_objectid_exists=555,
		nt_status_convert_to_large=556,
		nt_status_retry=557,
		nt_status_found_out_of_scope=558,
		nt_status_allocate_bucket=559,
		nt_status_propset_not_found=560,
		nt_status_marshall_overflow=561,
		nt_status_invalid_variant=562,
		nt_status_domain_controller_not_found=563,
		nt_status_account_locked_out=564,
		nt_status_handle_not_closable=565,
		nt_status_connection_refused=566,
		nt_status_graceful_disconnect=567,
		nt_status_address_already_associated=568,
		nt_status_address_not_associated=569,
		nt_status_connection_invalid=570,
		nt_status_connection_active=571,
		nt_status_network_unreachable=572,
		nt_status_host_unreachable=573,
		nt_status_protocol_unreachable=574,
		nt_status_port_unreachable=575,
		nt_status_request_aborted=576,
		nt_status_connection_aborted=577,
		nt_status_bad_compression_buffer=578,
		nt_status_user_mapped_file=579,
		nt_status_audit_failed=580,
		nt_status_timer_resolution_not_set=581,
		nt_status_connection_count_limit=582,
		nt_status_login_time_restriction=583,
		nt_status_login_wksta_restriction=584,
		nt_status_image_mp_up_mismatch=585,
		nt_status_insufficient_logon_info=592,
		nt_status_bad_dll_entrypoint=593,
		nt_status_bad_service_entrypoint=594,
		nt_status_lpc_reply_lost=595,
		nt_status_ip_address_conflict1=596,
		nt_status_ip_address_conflict2=597,
		nt_status_registry_quota_limit=598,
		nt_status_path_not_covered=599,
		nt_status_no_callback_active=600,
		nt_status_license_quota_exceeded=601,
		nt_status_pwd_too_short=602,
		nt_status_pwd_too_recent=603,
		nt_status_pwd_history_conflict=604,
		nt_status_plugplay_no_device=606,
		nt_status_unsupported_compression=607,
		nt_status_invalid_hw_profile=608,
		nt_status_invalid_plugplay_device_path=609,
		nt_status_driver_ordinal_not_found=610,
		nt_status_driver_entrypoint_not_found=611,
		nt_status_resource_not_owned=612,
		nt_status_too_many_links=613,
		nt_status_quota_list_inconsistent=614,
		nt_status_file_is_offline=615,
		// nt_status_notify_enum_dir=268,
	};

	struct error_label_entry
	{
		int code;
		const char * label;
	};

	static const struct error_label_entry dos_errors[] =
	{
		{ 0, "not specified" },
		{ errdos_badfunc, "badfunc" },
		{ errdos_badfile, "badfile" },
		{ errdos_badpath, "badpath" },
		{ errdos_nofids, "nofids" },
		{ errdos_noaccess, "noaccess" },
		{ errdos_badfid, "badfid" },
		{ errdos_badmcb, "badmcb" },
		{ errdos_nomem, "nomem" },
		{ errdos_badmem, "badmem" },
		{ errdos_badenv, "badenv" },
		{ errdos_badformat, "badformat" },
		{ errdos_badaccess, "badaccess" },
		{ errdos_baddata, "baddata" },
		{ errdos_baddrive, "baddrive" },
		{ errdos_remcd, "remcd" },
		{ errdos_diffdevice, "diffdevice" },
		{ errdos_nofiles, "nofiles" },
		{ errdos_badshare, "badshare" },
		{ errdos_lock, "lock" },
		{ errdos_filexists, "filexists" },
		{ errdos_quota, "quota" },
		{ errdos_notALink, "notALink" },
		{ -1, NULL }
	};

	static const struct error_label_entry server_errors[] =
	{
		{ 0, "not specified" },
		{ errsrv_error, "error" },
		{ errsrv_badpw, "badpw" },
		{ errsrv_access, "access" },
		{ errsrv_invtid, "invtid" },
		{ errsrv_invnetname, "invnetname" },
		{ errsrv_invdevice, "invdevice" },
		{ errsrv_qfull, "qfull" },
		{ errsrv_qtoobig, "qtoobig" },
		{ errsrv_qeof, "qeof" },
		{ errsrv_invpfid, "invpfid" },
		{ errsrv_smbcmd, "smbcmd" },
		{ errsrv_srverror, "srverror" },
		{ errsrv_badBID, "badBID" },
		{ errsrv_filespecs, "filespecs" },
		{ errsrv_badLink, "badLink" },
		{ errsrv_badpermits, "badpermits" },
		{ errsrv_badPID, "badPID" },
		{ errsrv_setattrmode, "setattrmode" },
		{ errsrv_paused, "paused" },
		{ errsrv_msgoff, "msgoff" },
		{ errsrv_noroom, "noroom" },
		{ errsrv_rmuns, "rmuns" },
		{ errsrv_timeout, "timeout" },
		{ errsrv_noresource, "noresource" },
		{ errsrv_toomanyuids, "toomanyuids" },
		{ errsrv_baduid, "baduid" },
		{ errsrv_usempx, "usempx" },
		{ errsrv_usestd, "usestd" },
		{ errsrv_contmpx, "contmpx" },
		{ errsrv_badPassword, "badPassword" },
		{ errsrv_notifyEnumDir, "notifyEnumDir" },
		{ errsrv_accountExpired, "accountExpired" },
		{ errsrv_badClient, "badClient" },
		{ errsrv_badLogonTime, "badLogonTime" },
		{ errsrv_passwordExpired, "passwordExpired" },
		{ errsrv_nosupport, "nosupport" },
		{ -1, NULL }
	};

	static const struct error_label_entry hardware_errors[] =
	{
		{ 0, "not specified" },
		{ errhrd_nowrite, "nowrite" },
		{ errhrd_badunit, "badunit" },
		{ errhrd_notready, "notready" },
		{ errhrd_badcmd, "badcmd" },
		{ errhrd_data, "data" },
		{ errhrd_badreq, "badreq" },
		{ errhrd_seek, "seek" },
		{ errhrd_badmedia, "badmedia" },
		{ errhrd_badsector, "badsector" },
		{ errhrd_nopaper, "nopaper" },
		{ errhrd_write, "write" },
		{ errhrd_read, "read" },
		{ errhrd_general, "general" },
		{ errhrd_badshare, "badshare" },
		{ errhrd_lock, "lock" },
		{ errhrd_wrongdisk, "wrongdisk" },
		{ errhrd_FCBUnavail, "FCBUnavail" },
		{ errhrd_sharebufexc, "sharebufexc" },
		{ -1, NULL }
	};

	static const struct error_label_entry nt_error_codes[] =
	{
		{ 0, "not specified" },
		{ nt_status_unsuccessful, "unsuccessful" },
		{ nt_status_not_implemented, "not_implemented" },
		{ nt_status_invalid_info_class, "invalid_info_class" },
		{ nt_status_info_length_mismatch, "info_length_mismatch" },
		{ nt_status_access_violation, "access_violation" },
		{ nt_status_in_page_error, "in_page_error" },
		{ nt_status_pagefile_quota, "pagefile_quota" },
		{ nt_status_invalid_handle, "invalid_handle" },
		{ nt_status_bad_initial_stack, "bad_initial_stack" },
		{ nt_status_bad_initial_pc, "bad_initial_pc" },
		{ nt_status_invalid_cid, "invalid_cid" },
		{ nt_status_timer_not_canceled, "timer_not_canceled" },
		{ nt_status_invalid_parameter, "invalid_parameter" },
		{ nt_status_no_such_device, "no_such_device" },
		{ nt_status_no_such_file, "no_such_file" },
		{ nt_status_invalid_device_request, "invalid_device_request" },
		{ nt_status_end_of_file, "end_of_file" },
		{ nt_status_wrong_volume, "wrong_volume" },
		{ nt_status_no_media_in_device, "no_media_in_device" },
		{ nt_status_unrecognized_media, "unrecognized_media" },
		{ nt_status_nonexistent_sector, "nonexistent_sector" },
		{ nt_status_more_processing_required, "more_processing_required" },
		{ nt_status_no_memory, "no_memory" },
		{ nt_status_conflicting_addresses, "conflicting_addresses" },
		{ nt_status_not_mapped_view, "not_mapped_view" },
		{ nt_status_unable_to_free_vm, "unable_to_free_vm" },
		{ nt_status_unable_to_delete_section, "unable_to_delete_section" },
		{ nt_status_invalid_system_service, "invalid_system_service" },
		{ nt_status_illegal_instruction, "illegal_instruction" },
		{ nt_status_invalid_lock_sequence, "invalid_lock_sequence" },
		{ nt_status_invalid_view_size, "invalid_view_size" },
		{ nt_status_invalid_file_for_section, "invalid_file_for_section" },
		{ nt_status_already_committed, "already_committed" },
		{ nt_status_access_denied, "access_denied" },
		{ nt_status_buffer_too_small, "buffer_too_small" },
		{ nt_status_object_type_mismatch, "object_type_mismatch" },
		{ nt_status_noncontinuable_exception, "noncontinuable_exception" },
		{ nt_status_invalid_disposition, "invalid_disposition" },
		{ nt_status_unwind, "unwind" },
		{ nt_status_bad_stack, "bad_stack" },
		{ nt_status_invalid_unwind_target, "invalid_unwind_target" },
		{ nt_status_not_locked, "not_locked" },
		{ nt_status_parity_error, "parity_error" },
		{ nt_status_unable_to_decommit_vm, "unable_to_decommit_vm" },
		{ nt_status_not_committed, "not_committed" },
		{ nt_status_invalid_port_attributes, "invalid_port_attributes" },
		{ nt_status_port_message_too_long, "port_message_too_long" },
		{ nt_status_invalid_parameter_mix, "invalid_parameter_mix" },
		{ nt_status_invalid_quota_lower, "invalid_quota_lower" },
		{ nt_status_disk_corrupt_error, "disk_corrupt_error" },
		{ nt_status_object_name_invalid, "object_name_invalid" },
		{ nt_status_object_name_not_found, "object_name_not_found" },
		{ nt_status_object_name_collision, "object_name_collision" },
		{ nt_status_handle_not_waitable, "handle_not_waitable" },
		{ nt_status_port_disconnected, "port_disconnected" },
		{ nt_status_device_already_attached, "device_already_attached" },
		{ nt_status_object_path_invalid, "object_path_invalid" },
		{ nt_status_object_path_not_found, "object_path_not_found" },
		{ nt_status_object_path_syntax_bad, "object_path_syntax_bad" },
		{ nt_status_data_overrun, "data_overrun" },
		{ nt_status_data_late_error, "data_late_error" },
		{ nt_status_data_error, "data_error" },
		{ nt_status_crc_error, "crc_error" },
		{ nt_status_section_too_big, "section_too_big" },
		{ nt_status_port_connection_refused, "port_connection_refused" },
		{ nt_status_invalid_port_handle, "invalid_port_handle" },
		{ nt_status_sharing_violation, "sharing_violation" },
		{ nt_status_quota_exceeded, "quota_exceeded" },
		{ nt_status_invalid_page_protection, "invalid_page_protection" },
		{ nt_status_mutant_not_owned, "mutant_not_owned" },
		{ nt_status_semaphore_limit_exceeded, "semaphore_limit_exceeded" },
		{ nt_status_port_already_set, "port_already_set" },
		{ nt_status_section_not_image, "section_not_image" },
		{ nt_status_suspend_count_exceeded, "suspend_count_exceeded" },
		{ nt_status_thread_is_terminating, "thread_is_terminating" },
		{ nt_status_bad_working_set_limit, "bad_working_set_limit" },
		{ nt_status_incompatible_file_map, "incompatible_file_map" },
		{ nt_status_section_protection, "section_protection" },
		{ nt_status_eas_not_supported, "eas_not_supported" },
		{ nt_status_ea_too_large, "ea_too_large" },
		{ nt_status_nonexistent_ea_entry, "nonexistent_ea_entry" },
		{ nt_status_no_eas_on_file, "no_eas_on_file" },
		{ nt_status_ea_corrupt_error, "ea_corrupt_error" },
		{ nt_status_file_lock_conflict, "file_lock_conflict" },
		{ nt_status_lock_not_granted, "lock_not_granted" },
		{ nt_status_delete_pending, "delete_pending" },
		{ nt_status_ctl_file_not_supported, "ctl_file_not_supported" },
		{ nt_status_unknown_revision, "unknown_revision" },
		{ nt_status_revision_mismatch, "revision_mismatch" },
		{ nt_status_invalid_owner, "invalid_owner" },
		{ nt_status_invalid_primary_group, "invalid_primary_group" },
		{ nt_status_no_impersonation_token, "no_impersonation_token" },
		{ nt_status_cant_disable_mandatory, "cant_disable_mandatory" },
		{ nt_status_no_logon_servers, "no_logon_servers" },
		{ nt_status_no_such_logon_session, "no_such_logon_session" },
		{ nt_status_no_such_privilege, "no_such_privilege" },
		{ nt_status_privilege_not_held, "privilege_not_held" },
		{ nt_status_invalid_account_name, "invalid_account_name" },
		{ nt_status_user_exists, "user_exists" },
		{ nt_status_no_such_user, "no_such_user" },
		{ nt_status_group_exists, "group_exists" },
		{ nt_status_no_such_group, "no_such_group" },
		{ nt_status_member_in_group, "member_in_group" },
		{ nt_status_member_not_in_group, "member_not_in_group" },
		{ nt_status_last_admin, "last_admin" },
		{ nt_status_wrong_password, "wrong_password" },
		{ nt_status_ill_formed_password, "ill_formed_password" },
		{ nt_status_password_restriction, "password_restriction" },
		{ nt_status_logon_failure, "logon_failure" },
		{ nt_status_account_restriction, "account_restriction" },
		{ nt_status_invalid_logon_hours, "invalid_logon_hours" },
		{ nt_status_invalid_workstation, "invalid_workstation" },
		{ nt_status_password_expired, "password_expired" },
		{ nt_status_account_disabled, "account_disabled" },
		{ nt_status_none_mapped, "none_mapped" },
		{ nt_status_too_many_luids_requested, "too_many_luids_requested" },
		{ nt_status_luids_exhausted, "luids_exhausted" },
		{ nt_status_invalid_sub_authority, "invalid_sub_authority" },
		{ nt_status_invalid_acl, "invalid_acl" },
		{ nt_status_invalid_sid, "invalid_sid" },
		{ nt_status_invalid_security_descr, "invalid_security_descr" },
		{ nt_status_procedure_not_found, "procedure_not_found" },
		{ nt_status_invalid_image_format, "invalid_image_format" },
		{ nt_status_no_token, "no_token" },
		{ nt_status_bad_inheritance_acl, "bad_inheritance_acl" },
		{ nt_status_range_not_locked, "range_not_locked" },
		{ nt_status_disk_full, "disk_full" },
		{ nt_status_server_disabled, "server_disabled" },
		{ nt_status_server_not_disabled, "server_not_disabled" },
		{ nt_status_too_many_guids_requested, "too_many_guids_requested" },
		{ nt_status_guids_exhausted, "guids_exhausted" },
		{ nt_status_invalid_id_authority, "invalid_id_authority" },
		{ nt_status_agents_exhausted, "agents_exhausted" },
		{ nt_status_invalid_volume_label, "invalid_volume_label" },
		{ nt_status_section_not_extended, "section_not_extended" },
		{ nt_status_not_mapped_data, "not_mapped_data" },
		{ nt_status_resource_data_not_found, "resource_data_not_found" },
		{ nt_status_resource_type_not_found, "resource_type_not_found" },
		{ nt_status_resource_name_not_found, "resource_name_not_found" },
		{ nt_status_array_bounds_exceeded, "array_bounds_exceeded" },
		{ nt_status_float_denormal_operand, "float_denormal_operand" },
		{ nt_status_float_divide_by_zero, "float_divide_by_zero" },
		{ nt_status_float_inexact_result, "float_inexact_result" },
		{ nt_status_float_invalid_operation, "float_invalid_operation" },
		{ nt_status_float_overflow, "float_overflow" },
		{ nt_status_float_stack_check, "float_stack_check" },
		{ nt_status_float_underflow, "float_underflow" },
		{ nt_status_integer_divide_by_zero, "integer_divide_by_zero" },
		{ nt_status_integer_overflow, "integer_overflow" },
		{ nt_status_privileged_instruction, "privileged_instruction" },
		{ nt_status_too_many_paging_files, "too_many_paging_files" },
		{ nt_status_file_invalid, "file_invalid" },
		{ nt_status_allotted_space_exceeded, "allotted_space_exceeded" },
		{ nt_status_insufficient_resources, "insufficient_resources" },
		{ nt_status_dfs_exit_path_found, "dfs_exit_path_found" },
		{ nt_status_device_data_error, "device_data_error" },
		{ nt_status_device_not_connected, "device_not_connected" },
		{ nt_status_device_power_failure, "device_power_failure" },
		{ nt_status_free_vm_not_at_base, "free_vm_not_at_base" },
		{ nt_status_memory_not_allocated, "memory_not_allocated" },
		{ nt_status_working_set_quota, "working_set_quota" },
		{ nt_status_media_write_protected, "media_write_protected" },
		{ nt_status_device_not_ready, "device_not_ready" },
		{ nt_status_invalid_group_attributes, "invalid_group_attributes" },
		{ nt_status_bad_impersonation_level, "bad_impersonation_level" },
		{ nt_status_cant_open_anonymous, "cant_open_anonymous" },
		{ nt_status_bad_validation_class, "bad_validation_class" },
		{ nt_status_bad_token_type, "bad_token_type" },
		{ nt_status_bad_master_boot_record, "bad_master_boot_record" },
		{ nt_status_instruction_misalignment, "instruction_misalignment" },
		{ nt_status_instance_not_available, "instance_not_available" },
		{ nt_status_pipe_not_available, "pipe_not_available" },
		{ nt_status_invalid_pipe_state, "invalid_pipe_state" },
		{ nt_status_pipe_busy, "pipe_busy" },
		{ nt_status_illegal_function, "illegal_function" },
		{ nt_status_pipe_disconnected, "pipe_disconnected" },
		{ nt_status_pipe_closing, "pipe_closing" },
		{ nt_status_pipe_connected, "pipe_connected" },
		{ nt_status_pipe_listening, "pipe_listening" },
		{ nt_status_invalid_read_mode, "invalid_read_mode" },
		{ nt_status_io_timeout, "io_timeout" },
		{ nt_status_file_forced_closed, "file_forced_closed" },
		{ nt_status_profiling_not_started, "profiling_not_started" },
		{ nt_status_profiling_not_stopped, "profiling_not_stopped" },
		{ nt_status_could_not_interpret, "could_not_interpret" },
		{ nt_status_file_is_a_directory, "file_is_a_directory" },
		{ nt_status_not_supported, "not_supported" },
		{ nt_status_remote_not_listening, "remote_not_listening" },
		{ nt_status_duplicate_name, "duplicate_name" },
		{ nt_status_bad_network_path, "bad_network_path" },
		{ nt_status_network_busy, "network_busy" },
		{ nt_status_device_does_not_exist, "device_does_not_exist" },
		{ nt_status_too_many_commands, "too_many_commands" },
		{ nt_status_adapter_hardware_error, "adapter_hardware_error" },
		{ nt_status_invalid_network_response, "invalid_network_response" },
		{ nt_status_unexpected_network_error, "unexpected_network_error" },
		{ nt_status_bad_remote_adapter, "bad_remote_adapter" },
		{ nt_status_print_queue_full, "print_queue_full" },
		{ nt_status_no_spool_space, "no_spool_space" },
		{ nt_status_print_cancelled, "print_cancelled" },
		{ nt_status_network_name_deleted, "network_name_deleted" },
		{ nt_status_network_access_denied, "network_access_denied" },
		{ nt_status_bad_device_type, "bad_device_type" },
		{ nt_status_bad_network_name, "bad_network_name" },
		{ nt_status_too_many_names, "too_many_names" },
		{ nt_status_too_many_sessions, "too_many_sessions" },
		{ nt_status_sharing_paused, "sharing_paused" },
		{ nt_status_request_not_accepted, "request_not_accepted" },
		{ nt_status_redirector_paused, "redirector_paused" },
		{ nt_status_net_write_fault, "net_write_fault" },
		{ nt_status_profiling_at_limit, "profiling_at_limit" },
		{ nt_status_not_same_device, "not_same_device" },
		{ nt_status_file_renamed, "file_renamed" },
		{ nt_status_virtual_circuit_closed, "virtual_circuit_closed" },
		{ nt_status_no_security_on_object, "no_security_on_object" },
		{ nt_status_cant_wait, "cant_wait" },
		{ nt_status_pipe_empty, "pipe_empty" },
		{ nt_status_cant_access_domain_info, "cant_access_domain_info" },
		{ nt_status_cant_terminate_self, "cant_terminate_self" },
		{ nt_status_invalid_server_state, "invalid_server_state" },
		{ nt_status_invalid_domain_state, "invalid_domain_state" },
		{ nt_status_invalid_domain_role, "invalid_domain_role" },
		{ nt_status_no_such_domain, "no_such_domain" },
		{ nt_status_domain_exists, "domain_exists" },
		{ nt_status_domain_limit_exceeded, "domain_limit_exceeded" },
		{ nt_status_oplock_not_granted, "oplock_not_granted" },
		{ nt_status_invalid_oplock_protocol, "invalid_oplock_protocol" },
		{ nt_status_internal_db_corruption, "internal_db_corruption" },
		{ nt_status_internal_error, "internal_error" },
		{ nt_status_generic_not_mapped, "generic_not_mapped" },
		{ nt_status_bad_descriptor_format, "bad_descriptor_format" },
		{ nt_status_invalid_user_buffer, "invalid_user_buffer" },
		{ nt_status_unexpected_io_error, "unexpected_io_error" },
		{ nt_status_unexpected_mm_create_err, "unexpected_mm_create_err" },
		{ nt_status_unexpected_mm_map_error, "unexpected_mm_map_error" },
		{ nt_status_unexpected_mm_extend_err, "unexpected_mm_extend_err" },
		{ nt_status_not_logon_process, "not_logon_process" },
		{ nt_status_logon_session_exists, "logon_session_exists" },
		{ nt_status_invalid_parameter_1, "invalid_parameter_1" },
		{ nt_status_invalid_parameter_2, "invalid_parameter_2" },
		{ nt_status_invalid_parameter_3, "invalid_parameter_3" },
		{ nt_status_invalid_parameter_4, "invalid_parameter_4" },
		{ nt_status_invalid_parameter_5, "invalid_parameter_5" },
		{ nt_status_invalid_parameter_6, "invalid_parameter_6" },
		{ nt_status_invalid_parameter_7, "invalid_parameter_7" },
		{ nt_status_invalid_parameter_8, "invalid_parameter_8" },
		{ nt_status_invalid_parameter_9, "invalid_parameter_9" },
		{ nt_status_invalid_parameter_10, "invalid_parameter_10" },
		{ nt_status_invalid_parameter_11, "invalid_parameter_11" },
		{ nt_status_invalid_parameter_12, "invalid_parameter_12" },
		{ nt_status_redirector_not_started, "redirector_not_started" },
		{ nt_status_redirector_started, "redirector_started" },
		{ nt_status_stack_overflow, "stack_overflow" },
		{ nt_status_no_such_package, "no_such_package" },
		{ nt_status_bad_function_table, "bad_function_table" },
		{ nt_status_directory_not_empty, "directory_not_empty" },
		{ nt_status_file_corrupt_error, "file_corrupt_error" },
		{ nt_status_not_a_directory, "not_a_directory" },
		{ nt_status_bad_logon_session_state, "bad_logon_session_state" },
		{ nt_status_logon_session_collision, "logon_session_collision" },
		{ nt_status_name_too_long, "name_too_long" },
		{ nt_status_files_open, "files_open" },
		{ nt_status_connection_in_use, "connection_in_use" },
		{ nt_status_message_not_found, "message_not_found" },
		{ nt_status_process_is_terminating, "process_is_terminating" },
		{ nt_status_invalid_logon_type, "invalid_logon_type" },
		{ nt_status_no_guid_translation, "no_guid_translation" },
		{ nt_status_cannot_impersonate, "cannot_impersonate" },
		{ nt_status_image_already_loaded, "image_already_loaded" },
		{ nt_status_abios_not_present, "abios_not_present" },
		{ nt_status_abios_lid_not_exist, "abios_lid_not_exist" },
		{ nt_status_abios_lid_already_owned, "abios_lid_already_owned" },
		{ nt_status_abios_not_lid_owner, "abios_not_lid_owner" },
		{ nt_status_abios_invalid_command, "abios_invalid_command" },
		{ nt_status_abios_invalid_lid, "abios_invalid_lid" },
		{ nt_status_abios_selector_not_available, "abios_selector_not_available" },
		{ nt_status_abios_invalid_selector, "abios_invalid_selector" },
		{ nt_status_no_ldt, "no_ldt" },
		{ nt_status_invalid_ldt_size, "invalid_ldt_size" },
		{ nt_status_invalid_ldt_offset, "invalid_ldt_offset" },
		{ nt_status_invalid_ldt_descriptor, "invalid_ldt_descriptor" },
		{ nt_status_invalid_image_ne_format, "invalid_image_ne_format" },
		{ nt_status_rxact_invalid_state, "rxact_invalid_state" },
		{ nt_status_rxact_commit_failure, "rxact_commit_failure" },
		{ nt_status_mapped_file_size_zero, "mapped_file_size_zero" },
		{ nt_status_too_many_opened_files, "too_many_opened_files" },
		{ nt_status_cancelled, "cancelled" },
		{ nt_status_cannot_delete, "cannot_delete" },
		{ nt_status_invalid_computer_name, "invalid_computer_name" },
		{ nt_status_file_deleted, "file_deleted" },
		{ nt_status_special_account, "special_account" },
		{ nt_status_special_group, "special_group" },
		{ nt_status_special_user, "special_user" },
		{ nt_status_members_primary_group, "members_primary_group" },
		{ nt_status_file_closed, "file_closed" },
		{ nt_status_too_many_threads, "too_many_threads" },
		{ nt_status_thread_not_in_process, "thread_not_in_process" },
		{ nt_status_token_already_in_use, "token_already_in_use" },
		{ nt_status_pagefile_quota_exceeded, "pagefile_quota_exceeded" },
		{ nt_status_commitment_limit, "commitment_limit" },
		{ nt_status_invalid_image_le_format, "invalid_image_le_format" },
		{ nt_status_invalid_image_not_mz, "invalid_image_not_mz" },
		{ nt_status_invalid_image_protect, "invalid_image_protect" },
		{ nt_status_invalid_image_win_16, "invalid_image_win_16" },
		{ nt_status_logon_server_conflict, "logon_server_conflict" },
		{ nt_status_time_difference_at_dc, "time_difference_at_dc" },
		{ nt_status_synchronization_required, "synchronization_required" },
		{ nt_status_dll_not_found, "dll_not_found" },
		{ nt_status_open_failed, "open_failed" },
		{ nt_status_io_privilege_failed, "io_privilege_failed" },
		{ nt_status_ordinal_not_found, "ordinal_not_found" },
		{ nt_status_entrypoint_not_found, "entrypoint_not_found" },
		{ nt_status_control_c_exit, "control_c_exit" },
		{ nt_status_local_disconnect, "local_disconnect" },
		{ nt_status_remote_disconnect, "remote_disconnect" },
		{ nt_status_remote_resources, "remote_resources" },
		{ nt_status_link_failed, "link_failed" },
		{ nt_status_link_timeout, "link_timeout" },
		{ nt_status_invalid_connection, "invalid_connection" },
		{ nt_status_invalid_address, "invalid_address" },
		{ nt_status_dll_init_failed, "dll_init_failed" },
		{ nt_status_missing_systemfile, "missing_systemfile" },
		{ nt_status_unhandled_exception, "unhandled_exception" },
		{ nt_status_app_init_failure, "app_init_failure" },
		{ nt_status_pagefile_create_failed, "pagefile_create_failed" },
		{ nt_status_no_pagefile, "no_pagefile" },
		{ nt_status_invalid_level, "invalid_level" },
		{ nt_status_wrong_password_core, "wrong_password_core" },
		{ nt_status_illegal_float_context, "illegal_float_context" },
		{ nt_status_pipe_broken, "pipe_broken" },
		{ nt_status_registry_corrupt, "registry_corrupt" },
		{ nt_status_registry_io_failed, "registry_io_failed" },
		{ nt_status_no_event_pair, "no_event_pair" },
		{ nt_status_unrecognized_volume, "unrecognized_volume" },
		{ nt_status_serial_no_device_inited, "serial_no_device_inited" },
		{ nt_status_no_such_alias, "no_such_alias" },
		{ nt_status_member_not_in_alias, "member_not_in_alias" },
		{ nt_status_member_in_alias, "member_in_alias" },
		{ nt_status_alias_exists, "alias_exists" },
		{ nt_status_logon_not_granted, "logon_not_granted" },
		{ nt_status_too_many_secrets, "too_many_secrets" },
		{ nt_status_secret_too_long, "secret_too_long" },
		{ nt_status_internal_db_error, "internal_db_error" },
		{ nt_status_fullscreen_mode, "fullscreen_mode" },
		{ nt_status_too_many_context_ids, "too_many_context_ids" },
		{ nt_status_logon_type_not_granted, "logon_type_not_granted" },
		{ nt_status_not_registry_file, "not_registry_file" },
		{ nt_status_nt_cross_encryption_required, "nt_cross_encryption_required" },
		{ nt_status_domain_ctrlr_config_error, "domain_ctrlr_config_error" },
		{ nt_status_ft_missing_member, "ft_missing_member" },
		{ nt_status_ill_formed_service_entry, "ill_formed_service_entry" },
		{ nt_status_illegal_character, "illegal_character" },
		{ nt_status_unmappable_character, "unmappable_character" },
		{ nt_status_undefined_character, "undefined_character" },
		{ nt_status_floppy_volume, "floppy_volume" },
		{ nt_status_floppy_id_mark_not_found, "floppy_id_mark_not_found" },
		{ nt_status_floppy_wrong_cylinder, "floppy_wrong_cylinder" },
		{ nt_status_floppy_unknown_error, "floppy_unknown_error" },
		{ nt_status_floppy_bad_registers, "floppy_bad_registers" },
		{ nt_status_disk_recalibrate_failed, "disk_recalibrate_failed" },
		{ nt_status_disk_operation_failed, "disk_operation_failed" },
		{ nt_status_disk_reset_failed, "disk_reset_failed" },
		{ nt_status_shared_irq_busy, "shared_irq_busy" },
		{ nt_status_ft_orphaning, "ft_orphaning" },
		{ nt_status_partition_failure, "partition_failure" },
		{ nt_status_invalid_block_length, "invalid_block_length" },
		{ nt_status_device_not_partitioned, "device_not_partitioned" },
		{ nt_status_unable_to_lock_media, "unable_to_lock_media" },
		{ nt_status_unable_to_unload_media, "unable_to_unload_media" },
		{ nt_status_eom_overflow, "eom_overflow" },
		{ nt_status_no_media, "no_media" },
		{ nt_status_no_such_member, "no_such_member" },
		{ nt_status_invalid_member, "invalid_member" },
		{ nt_status_key_deleted, "key_deleted" },
		{ nt_status_no_log_space, "no_log_space" },
		{ nt_status_too_many_sids, "too_many_sids" },
		{ nt_status_lm_cross_encryption_required, "lm_cross_encryption_required" },
		{ nt_status_key_has_children, "key_has_children" },
		{ nt_status_child_must_be_volatile, "child_must_be_volatile" },
		{ nt_status_device_configuration_error, "device_configuration_error" },
		{ nt_status_driver_internal_error, "driver_internal_error" },
		{ nt_status_invalid_device_state, "invalid_device_state" },
		{ nt_status_io_device_error, "io_device_error" },
		{ nt_status_device_protocol_error, "device_protocol_error" },
		{ nt_status_backup_controller, "backup_controller" },
		{ nt_status_log_file_full, "log_file_full" },
		{ nt_status_too_late, "too_late" },
		{ nt_status_no_trust_lsa_secret, "no_trust_lsa_secret" },
		{ nt_status_no_trust_sam_account, "no_trust_sam_account" },
		{ nt_status_trusted_domain_failure, "trusted_domain_failure" },
		{ nt_status_trusted_relationship_failure, "trusted_relationship_failure" },
		{ nt_status_eventlog_file_corrupt, "eventlog_file_corrupt" },
		{ nt_status_eventlog_cant_start, "eventlog_cant_start" },
		{ nt_status_trust_failure, "trust_failure" },
		{ nt_status_mutant_limit_exceeded, "mutant_limit_exceeded" },
		{ nt_status_netlogon_not_started, "netlogon_not_started" },
		{ nt_status_account_expired, "account_expired" },
		{ nt_status_possible_deadlock, "possible_deadlock" },
		{ nt_status_network_credential_conflict, "network_credential_conflict" },
		{ nt_status_remote_session_limit, "remote_session_limit" },
		{ nt_status_eventlog_file_changed, "eventlog_file_changed" },
		{ nt_status_nologon_interdomain_trust_account, "nologon_interdomain_trust_account" },
		{ nt_status_nologon_workstation_trust_account, "nologon_workstation_trust_account" },
		{ nt_status_nologon_server_trust_account, "nologon_server_trust_account" },
		{ nt_status_domain_trust_inconsistent, "domain_trust_inconsistent" },
		{ nt_status_fs_driver_required, "fs_driver_required" },
		{ nt_status_no_user_session_key, "no_user_session_key" },
		{ nt_status_user_session_deleted, "user_session_deleted" },
		{ nt_status_resource_lang_not_found, "resource_lang_not_found" },
		{ nt_status_insuff_server_resources, "insuff_server_resources" },
		{ nt_status_invalid_buffer_size, "invalid_buffer_size" },
		{ nt_status_invalid_address_component, "invalid_address_component" },
		{ nt_status_invalid_address_wildcard, "invalid_address_wildcard" },
		{ nt_status_too_many_addresses, "too_many_addresses" },
		{ nt_status_address_already_exists, "address_already_exists" },
		{ nt_status_address_closed, "address_closed" },
		{ nt_status_connection_disconnected, "connection_disconnected" },
		{ nt_status_connection_reset, "connection_reset" },
		{ nt_status_too_many_nodes, "too_many_nodes" },
		{ nt_status_transaction_aborted, "transaction_aborted" },
		{ nt_status_transaction_timed_out, "transaction_timed_out" },
		{ nt_status_transaction_no_release, "transaction_no_release" },
		{ nt_status_transaction_no_match, "transaction_no_match" },
		{ nt_status_transaction_responded, "transaction_responded" },
		{ nt_status_transaction_invalid_id, "transaction_invalid_id" },
		{ nt_status_transaction_invalid_type, "transaction_invalid_type" },
		{ nt_status_not_server_session, "not_server_session" },
		{ nt_status_not_client_session, "not_client_session" },
		{ nt_status_cannot_load_registry_file, "cannot_load_registry_file" },
		{ nt_status_debug_attach_failed, "debug_attach_failed" },
		{ nt_status_system_process_terminated, "system_process_terminated" },
		{ nt_status_data_not_accepted, "data_not_accepted" },
		{ nt_status_no_browser_servers_found, "no_browser_servers_found" },
		{ nt_status_vdm_hard_error, "vdm_hard_error" },
		{ nt_status_driver_cancel_timeout, "driver_cancel_timeout" },
		{ nt_status_reply_message_mismatch, "reply_message_mismatch" },
		{ nt_status_mapped_alignment, "mapped_alignment" },
		{ nt_status_image_checksum_mismatch, "image_checksum_mismatch" },
		{ nt_status_lost_writebehind_data, "lost_writebehind_data" },
		{ nt_status_client_server_parameters_invalid, "client_server_parameters_invalid" },
		{ nt_status_password_must_change, "password_must_change" },
		{ nt_status_not_found, "not_found" },
		{ nt_status_not_tiny_stream, "not_tiny_stream" },
		{ nt_status_recovery_failure, "recovery_failure" },
		{ nt_status_stack_overflow_read, "stack_overflow_read" },
		{ nt_status_fail_check, "fail_check" },
		{ nt_status_duplicate_objectid, "duplicate_objectid" },
		{ nt_status_objectid_exists, "objectid_exists" },
		{ nt_status_convert_to_large, "convert_to_large" },
		{ nt_status_retry, "retry" },
		{ nt_status_found_out_of_scope, "found_out_of_scope" },
		{ nt_status_allocate_bucket, "allocate_bucket" },
		{ nt_status_propset_not_found, "propset_not_found" },
		{ nt_status_marshall_overflow, "marshall_overflow" },
		{ nt_status_invalid_variant, "invalid_variant" },
		{ nt_status_domain_controller_not_found, "domain_controller_not_found" },
		{ nt_status_account_locked_out, "account_locked_out" },
		{ nt_status_handle_not_closable, "handle_not_closable" },
		{ nt_status_connection_refused, "connection_refused" },
		{ nt_status_graceful_disconnect, "graceful_disconnect" },
		{ nt_status_address_already_associated, "address_already_associated" },
		{ nt_status_address_not_associated, "address_not_associated" },
		{ nt_status_connection_invalid, "connection_invalid" },
		{ nt_status_connection_active, "connection_active" },
		{ nt_status_network_unreachable, "network_unreachable" },
		{ nt_status_host_unreachable, "host_unreachable" },
		{ nt_status_protocol_unreachable, "protocol_unreachable" },
		{ nt_status_port_unreachable, "port_unreachable" },
		{ nt_status_request_aborted, "request_aborted" },
		{ nt_status_connection_aborted, "connection_aborted" },
		{ nt_status_bad_compression_buffer, "bad_compression_buffer" },
		{ nt_status_user_mapped_file, "user_mapped_file" },
		{ nt_status_audit_failed, "audit_failed" },
		{ nt_status_timer_resolution_not_set, "timer_resolution_not_set" },
		{ nt_status_connection_count_limit, "connection_count_limit" },
		{ nt_status_login_time_restriction, "login_time_restriction" },
		{ nt_status_login_wksta_restriction, "login_wksta_restriction" },
		{ nt_status_image_mp_up_mismatch, "image_mp_up_mismatch" },
		{ nt_status_insufficient_logon_info, "insufficient_logon_info" },
		{ nt_status_bad_dll_entrypoint, "bad_dll_entrypoint" },
		{ nt_status_bad_service_entrypoint, "bad_service_entrypoint" },
		{ nt_status_lpc_reply_lost, "lpc_reply_lost" },
		{ nt_status_ip_address_conflict1, "ip_address_conflict1" },
		{ nt_status_ip_address_conflict2, "ip_address_conflict2" },
		{ nt_status_registry_quota_limit, "registry_quota_limit" },
		{ nt_status_path_not_covered, "path_not_covered" },
		{ nt_status_no_callback_active, "no_callback_active" },
		{ nt_status_license_quota_exceeded, "license_quota_exceeded" },
		{ nt_status_pwd_too_short, "pwd_too_short" },
		{ nt_status_pwd_too_recent, "pwd_too_recent" },
		{ nt_status_pwd_history_conflict, "pwd_history_conflict" },
		{ nt_status_plugplay_no_device, "plugplay_no_device" },
		{ nt_status_unsupported_compression, "unsupported_compression" },
		{ nt_status_invalid_hw_profile, "invalid_hw_profile" },
		{ nt_status_invalid_plugplay_device_path, "invalid_plugplay_device_path" },
		{ nt_status_driver_ordinal_not_found, "driver_ordinal_not_found" },
		{ nt_status_driver_entrypoint_not_found, "driver_entrypoint_not_found" },
		{ nt_status_resource_not_owned, "resource_not_owned" },
		{ nt_status_too_many_links, "too_many_links" },
		{ nt_status_quota_list_inconsistent, "quota_list_inconsistent" },
		{ nt_status_file_is_offline, "file_is_offline" },
		//{ nt_status_notify_enum_dir, "notify_enum_dir" },
		{ -1, NULL }
	};

	const char * command_name;
	struct line_buffer lb;

	if(smb_packet_source == smb_packet_from_consumer)
		Printf("message type = Request (client --> server)\n");
	else
		Printf("message type = Response (server --> client)\n");

	if(header->flags2 & SMB_FLAGS2_32BIT_STATUS)
	{
		int level,facility,error_code;
		const char * level_name;
		const char * facility_name = "?";
		const char * error_code_name = "?";
		int i;

		level = (header->status >> 29) & 0x3;
		facility = (header->status >> 16) & 0x0fff;
		error_code = header->status & 0xffff;

		switch(level)
		{
			case 0:

				level_name = "success";
				break;

			case 1:

				level_name = "information";
				break;

			case 2:

				level_name = "warning";
				break;

			case 3:
			default:

				level_name = "error";
				break;
		}

		for(i = 0 ; nt_error_codes[i].code != -1 ; i++)
		{
			if(nt_error_codes[i].code == error_code)
			{
				error_code_name = nt_error_codes[i].label;
				break;
			}
		}

		Printf("status = [%08lx] level:%s (%ld), facility:%s (%ld), code:%s (%ld)\n",header->status,level,level_name,facility,facility_name,error_code,error_code_name);
	}
	else
	{
		const char * error_class_name;
		int error_class_value;
		const char * error_code_name = "?";
		int error_code_value;
		int i;

		error_class_value = header->status >> 24;
		error_code_value = header->status & 0xffff;

		switch(error_class_value)
		{
			case 0:

				error_class_name = "success";
				error_code_name = "no error";
				break;

			case 1:

				error_class_name = "DOS error";

				for(i = 0 ; dos_errors[i].code != -1 ; i++)
				{
					if(dos_errors[i].code == error_code_value)
					{
						error_code_name = dos_errors[i].label;
						break;
					}
				}

				break;

			case 2:

				error_class_name = "server error";

				for(i = 0 ; server_errors[i].code != -1 ; i++)
				{
					if(server_errors[i].code == error_code_value)
					{
						error_code_name = server_errors[i].label;
						break;
					}
				}

				break;

			case 3:

				error_class_name = "hardware error";

				for(i = 0 ; hardware_errors[i].code != -1 ; i++)
				{
					if(hardware_errors[i].code == error_code_value)
					{
						error_code_name = hardware_errors[i].label;
						break;
					}
				}

				break;

			default:

				error_class_name = "Command error";
				break;
		}

		Printf("status = error:%s (%ld), code:%s (%ld)\n",error_class_name,error_class_value,error_code_name,error_code_value);
	}

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
		add_lb_flag(&lb,"string-format=Unicode");
	else
		add_lb_flag(&lb,"string-format=ASCII");

	if(header->flags2 & SMB_FLAGS2_32BIT_STATUS)
		add_lb_flag(&lb,"status-code=NT_STATUS format");
	else
		add_lb_flag(&lb,"status-code=DOS error format");

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
		add_lb_flag(&lb,"name-format=long");
	else
		add_lb_flag(&lb,"name-format=8.3");

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

	Printf("length = %ld (packet size:%ld, buffer size:%ld)\n",header_length,packet_size,max_buffer_size);

	if(is_smb_andx_command(header->command))
	{
		const unsigned char * andx_header = (const unsigned char *)header->parameters;
		int offset = (((int)andx_header[3]) << 8) + andx_header[2];
		int num_parameter_words,num_data_bytes;

		command_name = get_smb_command_name(header->command);

		if(command_name != NULL)
			Printf("command = %s (ANDX)\n",command_name);
		else
			Printf("command = 0x%02lx (ANDX)\n",header->command);

		Printf("parameter words = %ld\n",header->num_parameter_words - 2);
		
		if(header->num_parameter_words - 2 > 0)
			print_smb_parameters(header->num_parameter_words - 2,&header->parameters[4]);

		Printf("data bytes = %ld\n",header->num_data_bytes);

		/* If there are any data bytes, print them like "type hex .." would. */
		if(header->num_data_bytes > 0)
			print_smb_data(&lb,header->num_data_bytes,header->data);

		print_smb_contents(header, header->command, smb_packet_source, header->num_parameter_words - 2, &header->parameters[4], header->num_data_bytes, header->data);

		while(andx_header[0] != 0xff && offset > 0 && offset < packet_size)
		{
			andx_header = &packet[offset];

			num_parameter_words = (*andx_header++);

			command_name = get_smb_command_name(andx_header[0]);

			if(command_name != NULL)
				Printf("command = %s (ANDX)\n",command_name);
			else
				Printf("command = 0x%02lx (ANDX)\n",header->command);

			Printf("andx_offset = 0x%02lx\n",(((int)andx_header[3]) << 8) + andx_header[2]);

			Printf("parameter words = %ld\n",num_parameter_words);
	
			if(num_parameter_words > 0)
				print_smb_parameters(num_parameter_words,&andx_header[4]);

			num_data_bytes = andx_header[4 + num_parameter_words * 2] + (((int)andx_header[4 + num_parameter_words * 2 + 1]) << 8);

			Printf("data bytes = %ld\n",num_data_bytes);

			if(num_data_bytes > 0)
				print_smb_data(&lb,num_data_bytes,&andx_header[4 + num_parameter_words * 2 + 2]);

			print_smb_contents(header, andx_header[0], smb_packet_source, num_parameter_words, &andx_header[4], num_data_bytes, &andx_header[4 + num_parameter_words * 2 + 2]);

			offset = (((int)andx_header[3]) << 8) + andx_header[2];
		}
	}
	else
	{
		command_name = get_smb_command_name(header->command);

		if(command_name != NULL)
			Printf("command = %s\n",command_name);
		else
			Printf("command = 0x%02lx\n",header->command);

		Printf("parameter words = %ld\n",header->num_parameter_words);
		
		if(header->num_parameter_words > 0)
			print_smb_parameters(header->num_parameter_words,(unsigned char *)header->parameters);

		Printf("data bytes = %ld\n",header->num_data_bytes);

		/* If there are any data bytes, print them like "type hex .." would. */
		if(header->num_data_bytes > 0)
			print_smb_data(&lb,header->num_data_bytes,header->data);

		print_smb_contents(header, header->command, smb_packet_source, header->num_parameter_words, header->parameters, header->num_data_bytes, header->data);
	}
}

/*****************************************************************************/

void
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

			print_smb_header(&header,num_bytes_read,packet,length,smb_packet_source,max_buffer_size);

			Printf("---\n\n");
		}
	}
}

/*****************************************************************************/

void
control_smb_dump(int enable)
{
	dump_smb_enabled = enable;
}
