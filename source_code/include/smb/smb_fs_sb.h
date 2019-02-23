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

#ifndef _SMB_H
#include <smb/smb.h>
#endif /* _SMB_H */

#ifndef _SMB_MOUNT_H
#include <smb/smb_mount.h>
#endif /* _SMB_MOUNT_H */

struct smb_server
{
	enum smb_protocol protocol;		/* The protocol this
									   connection accepts. */

	dword max_buffer_size;			/* Maximum SMB message size, including
									   message header, parameter and
									   data blocks */
	dword max_raw_size;				/* Maximum SMB_COM_WRITE_RAW and
									   SMB_COM_READ_RAW data. */
	dword smb_write_threshold;		/* If SMB header + payload size is smaller
									   than or equal to this threshold, send
									   both in a single combined send() operation
									   rather than separately. */
	dword smb_read_threshold;		/* Same as above, but for recv() operations. */
	int scatter_gather;				/* Use sendmsg() rather than send() where useful? */
	int tcp_no_delay;				/* Disable the Nagle algorithm for send()? */
	int socket_receive_buffer_size;	/* Desired socket receive buffer size, if > 0. */
	int socket_send_buffer_size;	/* Desired socket transmit buffer size, if > 0. */
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

	/* olsen (2018-06-01): UTF-16LE Unicode strings are used for path names. */
	int unicode_enabled;

	/* olsen (2018-08-12): Path names are case sensitive. */
	int case_sensitive;

	/* olsen (2018-08-12): Delay the use of Unicode strings during session setup. */
	int session_setup_delay_unicode;

	struct smba_server * abstraction;

	enum smb_conn_state state;

	/* The following are LANMAN 1.0 options transferred to us in SMBnegprot */
	dword capabilities;

	/* olsen (2012-12-10): raw SMB over TCP instead of NBT transport? */
	int raw_smb;

	/* olsen (2016-04-20): Use write-behind with SMB_COM_WRITE_RAW? */
	int write_behind;

	/* olsen (2018-05-09): Timeout for send/receive operations in seconds. */
	int timeout;

	/* olsen (2018-05-14): Don't retry establishing a server connection. */
	int dont_retry;

	/* olsen (2018-06-01): Enable Unicode support if the server supports it. */
	int use_unicode;

	/* olsen (2018-06-11): Prefer SMB core protocol commands over NT1 commands. */
	int prefer_core_protocol;

	/* olsen (2019-02-23): How many seconds will the directory cache remain valid? */
	int cache_expires;
};

#endif
