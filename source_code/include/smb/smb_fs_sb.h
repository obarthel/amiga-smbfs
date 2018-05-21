/*
 * :ts=4
 *
 * smb_fs_sb.h
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#ifndef _SMB_FS_SB
#define _SMB_FS_SB

#include <smb/smb.h>
#include <smb/smb_mount.h>

struct smb_server
{
	enum smb_protocol protocol;		/* The protocol this
									   connection accepts. */

	dword max_buffer_size;			/* Maximum SMB message size, including
									   message header, parameter and
									   data blocks */
	dword max_raw_size;				/* Maximum SMB_COM_WRITE_RAW and
									   SMB_COM_READ_RAW data. */
	int max_recv;					/* added by CS */
	word server_uid;
	word tid;

	struct smb_mount_data mount_data;	/* We store the complete information here
										   to be able to reconnect. */

	unsigned short rcls;				/* The error codes we received */
	unsigned short err;

	unsigned char *transmit_buffer;
	int transmit_buffer_size; /* Maximum size of the SMB message */
	int transmit_buffer_allocation_size; /* Amount of memory allocated for the transmit buffer */

	int security_mode;
	int crypt_key_length;
	unsigned char crypt_key[8];

	struct smba_server * abstraction;

	enum smb_conn_state state;

	/* The following are LANMAN 1.0 options transferred to us in SMBnegprot */
	dword capabilities;

	/* olsen (2012-12-10): raw SMB over TCP instead of NBT transport? */
	int raw_smb;

	/* olsen (2016-04-20): Use write-behind with SMB_COM_WRITE_RAW? */
	int write_behind;

	/* olsen (2016-04-20): Prefer SMB_COM_WRITE_RAW to SMB_COM_WRITE? */
	int prefer_write_raw;

	/* olsen (2018-05-08): Always use SMB_COM_WRITE, even if SMB_COM_WRITE_RAW were possible. */
	int disable_write_raw;

	/* olsen (2018-05-08): Always use SMB_COM_READ, even if SMB_COM_READ_RAW were possible. */
	int disable_read_raw;

	/* olsen (2018-05-09): Timeout for send/receive operations in seconds. */
	int timeout;

	/* olsen (2018-05-14): Don't retry establishing a server connection. */
	int dont_retry;

	/* olsen (2018-05-18): Override the "Native OS" name passed to the server. */
	char * native_os;
};

#endif
