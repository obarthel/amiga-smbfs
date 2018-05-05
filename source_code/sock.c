/*
 * :ts=4
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

/* Some message size calculations include the size of the NetBIOS session
 * header, which may not be necessary. The "message size" in question is not
 * the same as the underlying transport layer, which in this case is
 * NetBIOS over TCP.
 */
#define NETBIOS_HEADER_SIZE 4

/*****************************************************************************/

#include "smb_abstraction.h"
#include "dump_smb.h"

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

/*****************************************************************************/

/* smb_receive_raw: The NetBIOS header is only stored if want_header != 0. */
static int
smb_receive_raw (const struct smb_server *server, int sock_fd, unsigned char *target, int max_raw_length, int want_header)
{
	int len, result;
	int already_read;
	unsigned char netbios_session_buf[256];
	int netbios_session_payload_size;

 re_recv:

	/* Read the NetBIOS session header (rfc-1002, section 4.3.1) */
	result = recv (sock_fd, netbios_session_buf, NETBIOS_HEADER_SIZE, 0);
	if (result < 0)
	{
		LOG (("smb_receive_raw: recv error = %ld\n", errno));
		result = (-errno);
		goto out;
	}

	if (result < NETBIOS_HEADER_SIZE)
	{
		LOG (("smb_receive_raw: got less than %ld bytes\n", NETBIOS_HEADER_SIZE));
		result = -EIO;
		goto out;
	}

	netbios_session_payload_size = (int)smb_len(netbios_session_buf);
	SHOWVALUE(netbios_session_payload_size);

	#if defined(DUMP_SMB)
	{
		if(netbios_session_buf[0] != 0x00 && netbios_session_payload_size > 0)
		{
			if(netbios_session_payload_size > 256 - NETBIOS_HEADER_SIZE)
				netbios_session_payload_size = 256 - NETBIOS_HEADER_SIZE;

			result = recv (sock_fd, &netbios_session_buf[NETBIOS_HEADER_SIZE], netbios_session_payload_size - NETBIOS_HEADER_SIZE, 0);
			if (result < 0)
			{
				LOG (("smb_receive_raw: recv error = %ld\n", errno));

				result = (-errno);
				goto out;
			}

			if(result < netbios_session_payload_size - NETBIOS_HEADER_SIZE)
			{
				LOG (("smb_receive_raw: result (%ld) < %ld\n", result, netbios_session_payload_size - NETBIOS_HEADER_SIZE));

				result = -EIO;
				goto out;
			}

			dump_netbios_header(__FILE__,__LINE__,netbios_session_buf,&netbios_session_buf[NETBIOS_HEADER_SIZE],netbios_session_payload_size);
		}
		else
		{
			dump_netbios_header(__FILE__,__LINE__,netbios_session_buf,NULL,0);
		}
	}
	#endif /* defined(DUMP_SMB) */

	/* Check the session type. */
	switch (netbios_session_buf[0])
	{
		/* 0x00 == session message */
		case 0x00:

			break;

		/* 0x85 == session keepalive */
		case 0x85:

			LOG (("smb_receive_raw: Got SESSION KEEP ALIVE\n"));
			goto re_recv;

		/* 0x81 == session request */
		/* 0x82 == positive session response */
		/* 0x83 == negative session response */
		/* 0x84 == retarget session response */
		default:

			LOG (("smb_receive_raw: Invalid session header type 0x%02lx\n", netbios_session_buf[0]));

			result = -EIO;
			goto out;
	}

	/* The length in the RFC NB header is the raw data length (17 bits) */
	len = netbios_session_payload_size;
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
		if(NETBIOS_HEADER_SIZE + len > max_raw_length)
		{
			LOG (("smb_receive_raw: Received length (%ld) > max_xmit (%ld)!\n", len, max_raw_length));

			result = -EIO;
			goto out;
		}
	
		memcpy (target, netbios_session_buf, NETBIOS_HEADER_SIZE);
		target += NETBIOS_HEADER_SIZE;
	}

	for(already_read = 0 ; already_read < len ; already_read += result)
	{
		result = recv (sock_fd, (void *) (target + already_read), len - already_read, 0);
		if (result < 0)
		{
			LOG (("smb_receive_raw: recvfrom error = %ld\n", errno));

			result = (-errno);

			goto out;
		}
	}

	#if defined(DUMP_SMB)
	{
		/* If want_header==0 then this is the data returned by SMB_COM_READ_RAW. */
		dump_smb(__FILE__,__LINE__,!want_header,target,already_read,smb_packet_to_consumer,server->max_recv);
	}
	#endif /* defined(DUMP_SMB) */

	result = len;

 out:

	return result;
}

int
smb_receive (struct smb_server *server, int sock_fd)
{
	byte * packet = server->transmit_buffer;
	int result;

	ASSERT( server->max_recv <= server->transmit_buffer_size );

	result = smb_receive_raw (server, sock_fd, packet,
	                          server->max_recv - NETBIOS_HEADER_SIZE, /* max_xmit in server includes NB header */
	                          1); /* We want the header */
	if (result < 0)
	{
		LOG (("smb_receive: receive error: %ld\n", result));
		goto out;
	}

	server->rcls = *((unsigned char *) (packet + 9));
	server->err = WVAL (packet, 11);

	if (server->rcls != 0)
		LOG (("smb_receive: error class=%ld, error=%ld\n", server->rcls, server->err));

 out:

	return result;
}

/* smb_receive's preconditions also apply here. */
static int
smb_receive_trans2 (
	struct smb_server *	server,
	int					sock_fd,
	int *				data_len_ptr,
	int *				param_len_ptr,
	char **				data_ptr,
	char **				param_ptr)
{
	unsigned char *inbuf = server->transmit_buffer;
	int parameter_displacement;
	int parameter_count;
	int parameter_offset;
	int data_displacement;
	int data_count;
	int data_offset;
	int total_parameter_count;
	int total_data_count;

	int data_len;
	int param_len;
	char * data = NULL;
	char * param = NULL;
	int total_data;
	int total_param;
	int result;

	ASSERT( data_len_ptr != NULL );
	ASSERT( param_len_ptr != NULL );
	ASSERT( data_ptr != NULL );
	ASSERT( param_ptr != NULL );

	LOG (("smb_receive_trans2: enter\n"));

	(*data_len_ptr) = (*param_len_ptr) = 0;
	(*param_ptr) = (*data_ptr) = NULL;

	result = smb_receive (server, sock_fd);
	if (result < 0)
		goto fail;

	/* Is an error condition set? */
	if (server->rcls != 0)
		goto fail;

	/* parse out the lengths */
	total_data = WVAL (inbuf, smb_tdrcnt);
	total_param = WVAL (inbuf, smb_tprcnt);

	if ((total_data > server->max_recv) || (total_param > server->max_recv))
	{
		LOG (("smb_receive_trans2: data/param too long\n"));

		result = -EIO;
		goto fail;
	}

	/* Allocate it, but only if there is something to allocate
	 * in the first place.
	 */
	if(total_data > 0)
	{
		data = malloc (total_data);
		if (data == NULL)
		{
			LOG (("smb_receive_trans2: could not alloc data area\n"));

			result = -ENOMEM;
			goto fail;
		}
	}

	/* Allocate it, but only if there is something to allocate
	 * in the first place.
	 */
	if(total_param > 0)
	{
		param = malloc(total_param);
		if (param == NULL)
		{
			LOG (("smb_receive_trans2: could not alloc param area\n"));

			result = -ENOMEM;
			goto fail;
		}
	}

	LOG (("smb_rec_trans2: total_data/total_param: %ld/%ld\n", total_data, total_param));

	param_len = 0;
	data_len = 0;

	while (1)
	{
		parameter_displacement = WVAL (inbuf, smb_prdisp);
		parameter_count = WVAL (inbuf, smb_prcnt);
		parameter_offset = WVAL (inbuf, smb_proff);

		data_displacement = WVAL (inbuf, smb_drdisp);
		data_count = WVAL (inbuf, smb_drcnt);
		data_offset = WVAL (inbuf, smb_droff);

		total_parameter_count = WVAL (inbuf, smb_tprcnt);
		total_data_count = WVAL (inbuf, smb_tdrcnt);

		if (parameter_displacement + parameter_count > total_param)
		{
			LOG (("smb_receive_trans2: invalid parameters\n"));

			result = -EIO;
			goto fail;
		}

		if(param != NULL)
			memcpy (param + parameter_displacement, smb_base (inbuf) + parameter_offset, parameter_count);

		param_len += parameter_count;

		if (data_displacement + data_count > total_data)
		{
			LOG (("smb_receive_trans2: invalid data block\n"));

			result = -EIO;
			goto fail;
		}

		if(data != NULL)
			memcpy (data + data_displacement, smb_base (inbuf) + data_offset, data_count);

		data_len += data_count;

		LOG (("smb_rec_trans2: data count/parameter count: %ld/%ld\n", data_count, parameter_count));

		/* parse out the total lengths again - they can shrink! */
		if (total_data_count > total_data || total_parameter_count > total_param)
		{
			LOG (("smb_receive_trans2: data/params grew!\n"));

			result = -EIO;
			goto fail;
		}

		total_data = total_data_count;
		total_param = total_parameter_count;

		if (total_data <= data_len && total_param <= param_len)
			break;

		result = smb_receive (server, sock_fd);
		if (result < 0)
			goto fail;

		if (server->rcls != 0)
		{
			result = -smb_errno (server->rcls, server->err);
			goto fail;
		}
	}

	(*param_ptr) = param;
	(*param_len_ptr) = param_len;

	(*data_ptr) = data;
	(*data_len_ptr) = data_len;

	LOG (("smb_receive_trans2: normal exit\n"));
	return 0;

 fail:

	LOG (("smb_receive_trans2: failed exit\n"));

	if(param != NULL)
		free (param);

	if(data != NULL)
		free(data);

	return result;
}

void
smb_release (struct smb_server *server)
{
	if (server->mount_data.fd >= 0)
	{
		CloseSocket (server->mount_data.fd);
		server->mount_data.fd = -1;
	}
}

int
smb_connect (struct smb_server *server)
{
	int result;

	if(server->mount_data.fd < 0)
	{
		server->mount_data.fd = socket (AF_INET, SOCK_STREAM, 0);
		if (server->mount_data.fd < 0)
		{
			result = (-errno);
			goto out;
		}
	}

	LOG(("connecting to server %s\n", Inet_NtoA(server->mount_data.addr.sin_addr.s_addr)));

	result = connect (server->mount_data.fd, (struct sockaddr *)&server->mount_data.addr, sizeof(struct sockaddr_in));
	if(result < 0)
		result = (-errno);

 out:

	return(result);
}

/* Returns number of bytes received (>= 0) or a negative value in
 * case of error.
 */
int
smb_request (struct smb_server *server, const void * payload, int payload_size)
{
	int len, result;
	int sock_fd = server->mount_data.fd;
	unsigned char *buffer = server->transmit_buffer;

	if ((sock_fd < 0) || (buffer == NULL))
	{
		LOG (("smb_request: Bad server!\n"));

		result = -EBADF;
		goto out;
	}

	if (server->state != CONN_VALID)
	{
		LOG (("smb_request: Connection state is invalid\n"));

		result = -EIO;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	/* If there is a separate payload, only send the header
	 * here and take care of the payload later.
	 */
	if(payload != NULL && payload_size > 0)
	{
		ASSERT( payload_size < smb_len(buffer) );
		ASSERT( len > payload_size );

		len -= payload_size;
	}

	LOG (("smb_request: len = %ld, cmd = 0x%lx, payload=0x%08lx, payload_size=%ld\n", len, buffer[8], payload, payload_size));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,&buffer[NETBIOS_HEADER_SIZE],len);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	result = send (sock_fd, (void *) buffer, len, 0);
	if (result < 0)
	{
		LOG(("smb_request: send() for %ld bytes failed (errno=%ld)\n", len, errno));

		result = (-errno);
		goto out;
	}

	if(payload != NULL && payload_size > 0)
	{
		result = send (sock_fd, (void *)payload, payload_size, 0);
		if (result < 0)
		{
			LOG(("smb_request: payload send() for %ld bytes failed (errno=%ld)\n", payload_size, errno));

			result = (-errno);
			goto out;
		}
	}

	result = smb_receive (server, sock_fd);

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
 * one packet to send.
 */
int
smb_trans2_request (struct smb_server *server, int *data_len, int *param_len, char **data, char **param)
{
	int len, result;
	int sock_fd = server->mount_data.fd;
	unsigned char *buffer = server->transmit_buffer;

	if (server->state != CONN_VALID)
	{
		LOG (("smb_trans2_request: Connection state is invalid\n"));

		result = -EIO;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	LOG (("smb_request: len = %ld cmd = 0x%02lx\n", len, buffer[8]));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,NULL,0);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	result = send (sock_fd, (void *) buffer, len, 0);
	if (result < 0)
	{
		LOG(("smb_trans2_request: send() for %ld bytes failed (errno=%ld)\n", len, errno));

		result = (-errno);
		goto out;
	}

	result = smb_receive_trans2 (server, sock_fd, data_len, param_len, data, param);

 out:

	if (result < 0)
	{
		server->state = CONN_INVALID;
		smb_invalidate_all_inodes (server);
	}

	LOG (("smb_trans2_request: result = %ld\n", result));

	return result;
}

int
smb_request_read_raw (struct smb_server *server, unsigned char *target, int max_len)
{
	int len, result;
	int sock_fd = server->mount_data.fd;
	unsigned char *buffer = server->transmit_buffer;

	if (server->state != CONN_VALID)
	{
		LOG (("smb_trans2_request: Connection state is invalid\n"));

		result = -EIO;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	LOG (("smb_request_read_raw: len = %ld cmd = 0x%02lx\n", len, buffer[8]));
	LOG (("smb_request_read_raw: target=%lx, max_len=%ld\n", (unsigned int) target, max_len));
	LOG (("smb_request_read_raw: buffer=%lx, sock=%lx\n", (unsigned int) buffer, (unsigned int) sock_fd));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,NULL,0);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	/* Request that data should be read in raw mode. */
	result = send (sock_fd, (void *) buffer, len, 0);
	if (result < 0)
	{
		LOG(("smb_request_read_raw: send() for %ld bytes failed (errno=%ld)\n", len, errno));

		result = (-errno);
		goto out;
	}

	/* Wait for the raw data to be sent by the server. */
	result = smb_receive_raw (server, sock_fd, target, max_len, 0);

 out:

	if (result < 0)
	{
		server->state = CONN_INVALID;
		smb_invalidate_all_inodes (server);
	}

	LOG (("smb_request_read_raw: result = %ld\n", result));

	return result;
}

/* smb_request_write_raw assumes that the request SMBwriteBraw has been
 * completed successfully, so that we can send the raw data now.
 */
int
smb_request_write_raw (struct smb_server *server, unsigned const char *source, int length)
{
	byte nb_header[NETBIOS_HEADER_SIZE];
	int sock_fd = server->mount_data.fd;
	int result;

	if (server->state != CONN_VALID)
	{
		LOG (("smb_trans2_request: Connection state is invalid\n"));

		result = -EIO;
		goto out;
	}

	ASSERT( length <= 65535 );

	/* Send the NetBIOS header. */
	smb_encode_smb_length (nb_header, length);

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,nb_header,NULL,0);
	#endif /* defined(DUMP_SMB) */

	result = send (sock_fd, nb_header, NETBIOS_HEADER_SIZE, 0);
	if(result < 0)
	{
		LOG(("smb_request_write_raw: send() for %ld bytes failed (errno=%ld)\n", NETBIOS_HEADER_SIZE, errno));

		result = (-errno);
		goto out;
	}

	#if defined(DUMP_SMB)
	dump_smb(__FILE__,__LINE__,0,source,length,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	/* Now send the data to be written. */
	result = send (sock_fd, (void *)source, length, 0);
	if(result < 0)
	{
		LOG(("smb_request_write_raw: send() for %ld bytes failed (errno=%ld)\n", length, errno));

		result = (-errno);
		goto out;
	}

	/* Wait for the server to respond. */
	if(!server->write_behind)
	{
		result = smb_receive (server, sock_fd);
		if(result < 0)
			goto out;
	}
	else
	{
		LOG(("not waiting for server to respond\n"));
	}

	result = length;

 out:

	if (result < 0)
	{
		server->state = CONN_INVALID;

		smb_invalidate_all_inodes (server);
	}

	LOG (("smb_request_write_raw: result = %ld\n", result));

	return result;
}
