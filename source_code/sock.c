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
#include "errors.h"

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

/* Attempt to receive all the incoming data, even if recv() returns only
 * parts of the total number of bytes requested. Returns the number of bytes
 * read or, in case of error a negative number. A negative result is the
 * value of -errno.
 */
static int
receive_all(int fd, void * _data, int len, int * error_ptr)
{
	int num_bytes_received;
	char * data = _data;
	int result;

	ASSERT( data != NULL || len == 0 );
	ASSERT( error_ptr != NULL );

	for(num_bytes_received = 0 ; num_bytes_received < len ; num_bytes_received += result)
	{
		result = recv(fd, &data[num_bytes_received], len - num_bytes_received, 0);
		if(result == 0)
			break;

		if(result < 0)
		{
			(*error_ptr) = errno;
			goto out;
		}
	}

	result = num_bytes_received;

 out:

	return(result);
}

/*****************************************************************************/

/* smb_receive_raw: The NetBIOS header is only stored if want_header != 0. */
static int
smb_receive_raw (
	struct smb_server *	server,
	int					command,
	int					sock_fd,
	unsigned char *		target,
	int					max_raw_length,
	char *				input_payload,
	int					input_payload_size,
	int					want_header,
	int *				error_ptr)
{
	unsigned char netbios_session_buf[256];
	int netbios_session_payload_size;
	int len, result;

	ASSERT( error_ptr != NULL );

	server->rcls	= 0;
	server->err		= 0;

 re_recv:

	/* Read the NetBIOS session header (rfc-1002, section 4.3.1) */
	result = receive_all (sock_fd, netbios_session_buf, NETBIOS_HEADER_SIZE, error_ptr);
	if (result < 0)
	{
		LOG (("recv error = %ld\n", (*error_ptr)));
		goto out;
	}

	if (result < NETBIOS_HEADER_SIZE)
	{
		LOG (("got less than %ld bytes\n", NETBIOS_HEADER_SIZE));

		(*error_ptr) = error_end_of_file;

		result = -1;
		goto out;
	}

	netbios_session_payload_size = (int)smb_len(netbios_session_buf);
	SHOWVALUE(netbios_session_payload_size);

	#if defined(DUMP_SMB)
	{
		if(command != 0 && netbios_session_buf[0] != 0x00 && netbios_session_payload_size > 0)
		{
			/* We only want to show what's in the first few
			 * bytes of a session packet. Since we only support
			 * two session packet types (session message and
			 * session keep alive) we will abort processing
			 * anyway so it doesn't matter if we ignore any
			 * data beyond the first 256 bytes.
			 */
			if(netbios_session_payload_size > 256 - NETBIOS_HEADER_SIZE)
				netbios_session_payload_size = 256 - NETBIOS_HEADER_SIZE;

			result = receive_all (sock_fd, &netbios_session_buf[NETBIOS_HEADER_SIZE], netbios_session_payload_size - NETBIOS_HEADER_SIZE, error_ptr);
			if (result < 0)
			{
				LOG (("recv error = %ld\n", (*error_ptr)));
				goto out;
			}

			if(result < netbios_session_payload_size - NETBIOS_HEADER_SIZE)
			{
				LOG (("result (%ld) < %ld\n", result, netbios_session_payload_size - NETBIOS_HEADER_SIZE));

				(*error_ptr) = error_end_of_file;

				result = -1;
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

			LOG (("Got SESSION KEEP ALIVE\n"));
			goto re_recv;

		/* 0x81 == session request */
		/* 0x82 == positive session response */
		/* 0x83 == negative session response */
		/* 0x84 == retarget session response */
		default:

			/* The session setup may need to know about the
			 * NetBIOS session response, but for any command
			 * these message types are invalid.
			 */
			if(command != 0)
			{
				LOG (("Invalid session header type 0x%02lx\n", netbios_session_buf[0]));

				(*error_ptr) = error_invalid_netbios_session;

				result = -1;
				goto out;
			}

			break;
	}

	/* The length in the NetBIOS header is the raw data length (17 bits) */
	len = netbios_session_payload_size;
	if (len > max_raw_length)
	{
		LOG (("Received length (%ld) > max_xmit (%ld)!\n", len, max_raw_length));

		(*error_ptr) = error_message_exceeds_buffer_size;

		result = -1;
		goto out;
	}

	/* Prepend the NetBIOS header to what is read? */
	if (want_header)
	{
		memcpy (target, netbios_session_buf, NETBIOS_HEADER_SIZE);
		target += NETBIOS_HEADER_SIZE;
	}

	/* This is an optimization for the SMB_COM_READ and SMB_COM_READ_ANDX
	 * commands, which tries to avoid copying the received data twice. To
	 * this end we receive the command response up to the point at which
	 * the message header ends and the data returned by the server
	 * begins. Then we read the data, storing it directly in the
	 * receive buffer rather than in the packet buffer, from which
	 * it would otherwise have to be retrieved later.
	 */
	if(input_payload != NULL)
	{
		int num_bytes_received = 0;

		LOG(("input_payload=0x%08lx, payload_size=%ld\n", input_payload, input_payload_size));

		if(command == SMBreadX)
		{
			int data_length;
			int data_offset;

			/* We need to read the following data:
			 *
			 *  0:	32 bytes of SMB message header
			 * 32:	 1 byte of word count
			 * 33:	 1 byte of andxcommand
			 * 34:	 1 byte of andxreserved
			 * 35:	 2 bytes of andxoffset
			 * 37:	 2 bytes of available
			 * 39:	 2 bytes of datacompactionmode
			 * 41:	 2 bytes of reserved
			 * 43:	 2 bytes of datalength
			 * 45:	 2 bytes of dataoffset
			 * 47:	10 bytes of reserved
			 * 57:	 2 bytes of bytecount
			 *
			 * This adds up to 59 bytes.
			 */

			LOG(("SMBreadX: reading the first %ld bytes\n", 59));

			result = receive_all (sock_fd, target, 59, error_ptr);
			if (result < 0)
			{
				LOG (("recv error = %ld\n", (*error_ptr)));
				goto out;
			}

			num_bytes_received += result;

			ASSERT( num_bytes_received == 59 );

			/* End of file reached? */
			if(num_bytes_received < 59)
			{
				/* End of file */
				LOG (("EOF\n"));

				(*error_ptr) = error_end_of_file;
		
				result = -1;
				goto out;
			}

			data_offset = WVAL(target, 45);

			SHOWVALUE(data_offset);

			/* Skip the padding bytes, if any. */
			if(data_offset > 59)
			{
				result = receive_all (sock_fd, target + 59, data_offset - 59, error_ptr);
				if (result < 0)
				{
					LOG (("recv error = %ld\n", (*error_ptr)));
					goto out;
				}

				/* End of file reached? */
				if(result < data_offset - 59)
				{
					/* End of file */
					LOG (("EOF\n"));

					(*error_ptr) = error_end_of_file;
		
					result = -1;
					goto out;
				}

				num_bytes_received += result;
			}

			data_length = WVAL(target, 43);

			SHOWVALUE(data_length);

			result = receive_all (sock_fd, input_payload, data_length, error_ptr);
			if (result < 0)
			{
				LOG (("recv error = %ld\n", (*error_ptr)));
				goto out;
			}

			if(result < data_length)
			{
				/* End of file */
				LOG (("EOF\n"));

				(*error_ptr) = error_end_of_file;

				result = -1;
				goto out;
			}

			num_bytes_received += result;

			/* This should never happen, but then we better make sure to
			 * read the entire message.
			 */
			if(num_bytes_received < len)
			{
				LOG(("reading the remaining %ld bytes; this should never happen\n", len - num_bytes_received ));

				result = receive_all (sock_fd, &target[num_bytes_received], len - num_bytes_received, error_ptr);
				if (result < 0)
				{
					LOG (("recv error = %ld\n", (*error_ptr)));
					goto out;
				}

				if(result < len - num_bytes_received)
				{
					/* End of file */
					LOG (("EOF\n"));

					(*error_ptr) = error_end_of_file;

					result = -1;
					goto out;
				}
			}
		}
		else
		{
			int count_of_bytes_returned;
			int count_of_bytes_to_read;
			int buffer_format;

			ASSERT( command == SMBread );

			/* We need to read the following data:
			 *
			 *  0:	32 bytes of SMB message header
			 * 32:	 1 byte of word count
			 * 33:	 2 bytes of 'count of bytes returned' (1 word)
			 * 35:	 8 bytes of reserved data (4 words)
			 * 43:	 2 bytes of 'byte count' (1 word)
			 * 45:	 1 byte of 'buffer format'
			 * 46:	 2 bytes of 'count of bytes to read' (1 word).
			 *
			 * This adds up to 48 bytes.
			 */

			LOG(("SMBread: reading the first %ld bytes\n", 48));

			result = receive_all (sock_fd, target, 48, error_ptr);
			if (result < 0)
			{
				LOG (("recv error = %ld\n", (*error_ptr)));
				goto out;
			}

			num_bytes_received += result;

			ASSERT( num_bytes_received == 48 );

			/* End of file reached? */
			if(num_bytes_received < 48)
			{
				/* End of file */
				LOG (("EOF\n"));

				(*error_ptr) = error_end_of_file;
		
				result = -1;
				goto out;
			}

			/* So we read the header. Now we need to figure out if the
			 * data is in the expected format, and how many bytes are
			 * waiting to be read.
			 */

			/* The buffer format must be 1. */
			buffer_format = BVAL(target, 45);

			LOG(("buffer format = %ld, should be %ld\n", buffer_format, 1));

			if(buffer_format != 1)
			{
				LOG(("buffer format %ld not supported\n", buffer_format));

				(*error_ptr) = error_invalid_buffer_format;

				result = -1;
				goto out;
			}

			count_of_bytes_returned = WVAL(target, 33);
			count_of_bytes_to_read = WVAL(target, 46);

			/* That should never be more data than the read buffer may hold. */
			ASSERT( count_of_bytes_to_read <= input_payload_size );
			ASSERT( count_of_bytes_to_read <= count_of_bytes_returned );
			ASSERT( count_of_bytes_returned <= input_payload_size );

			LOG(("count of bytes to read = %ld, should be <= %ld\n", count_of_bytes_to_read, input_payload_size));

			if(count_of_bytes_returned > input_payload_size)
			{
				(*error_ptr) = error_message_exceeds_buffer_size;

				result = -1;
				goto out;
			}

			result = receive_all (sock_fd, input_payload, count_of_bytes_to_read, error_ptr);
			if (result < 0)
			{
				LOG (("recv error = %ld\n", (*error_ptr)));
				goto out;
			}

			if(result < count_of_bytes_to_read)
			{
				/* End of file */
				LOG (("EOF\n"));

				(*error_ptr) = error_end_of_file;

				result = -1;
				goto out;
			}

			num_bytes_received += result;

			ASSERT( count_of_bytes_to_read == count_of_bytes_returned );

			if(count_of_bytes_to_read < count_of_bytes_returned)
			{
				LOG(("fewer data available than should be delivered; setting the remainder (%ld bytes) to 0.\n", count_of_bytes_returned - count_of_bytes_to_read)); 

				memset(&input_payload[count_of_bytes_to_read],0,count_of_bytes_returned - count_of_bytes_to_read);
			}

			/* This should never happen, but then we better make sure to
			 * read the entire message.
			 */
			if(num_bytes_received < len)
			{
				LOG(("reading the remaining %ld bytes; this should never happen\n", len - num_bytes_received ));

				result = receive_all (sock_fd, &target[num_bytes_received], len - num_bytes_received, error_ptr);
				if (result < 0)
				{
					LOG (("recv error = %ld\n", (*error_ptr)));
					goto out;
				}

				if(result < len - num_bytes_received)
				{
					/* End of file */
					LOG (("EOF\n"));

					(*error_ptr) = error_end_of_file;

					result = -1;
					goto out;
				}
			}

			#if defined(DUMP_SMB)
			{
				/* If want_header==0 then this is the data returned by SMB_COM_READ_RAW. */
				dump_smb(__FILE__,__LINE__,!want_header,target,48,smb_packet_to_consumer,server->max_recv);

				if(buffer_format == 1)
					dump_smb(__FILE__,__LINE__,!want_header,input_payload,num_bytes_received - 48,smb_packet_to_consumer,server->max_recv);

				if(num_bytes_received < len && result > 0)
					dump_smb(__FILE__,__LINE__,!want_header,&target[num_bytes_received],result,smb_packet_to_consumer,server->max_recv);
			}
			#endif /* defined(DUMP_SMB) */
		}

		result = num_bytes_received;
	}
	else
	{
		result = receive_all (sock_fd, target, len, error_ptr);
		if (result < 0)
		{
			LOG (("recv error = %ld\n", (*error_ptr)));
			goto out;
		}

		if(result < len)
		{
			/* End of file */
			LOG (("EOF\n"));

			(*error_ptr) = error_end_of_file;

			result = -1;
			goto out;
		}

		#if defined(DUMP_SMB)
		{
			/* If want_header==0 then this is the data returned by SMB_COM_READ_RAW. */
			dump_smb(__FILE__,__LINE__,!want_header,target,result,smb_packet_to_consumer,server->max_recv);
		}
		#endif /* defined(DUMP_SMB) */
	}

 out:

	return result;
}

static int
smb_receive (struct smb_server *server, int command, int sock_fd, void * input_payload, int payload_size, int * error_ptr)
{
	byte * packet = server->transmit_buffer;
	int result;

	ASSERT( error_ptr != NULL );
	ASSERT( server->max_recv <= server->transmit_buffer_allocation_size );

	result = smb_receive_raw (
		server,
		command,
		sock_fd,
		packet,
		/* Note: Worst case, if the inbound data has to go into the buffer, with
		 *       no separate payload buffer provided. This is a "workaround" for
		 *       SMB_COM_READ_ANDX which can end up receiving the regular
		 *       SMB message header plus 65535 bytes of payload data, which
		 *       easily breaks the limit set by server->max_recv (which only
		 *       accounts for the in-band reception limit, not the out-of-band
		 *       limit if the "large readx" capability is in effect).
		 *       ZZZ this merits another check in smb_receive_raw().
		 */
		server->transmit_buffer_allocation_size,
		input_payload, payload_size,
		/* We want the NetBIOS session service header */
		TRUE,
		error_ptr);

	if (result < 0)
	{
		LOG (("receive error: %ld\n", (*error_ptr)));
		goto out;
	}

	/* The caller is responsible for dealing with the error
	 * information.
	 */
	server->rcls	= BVAL (packet, 9);
	server->err		= WVAL (packet, 11);

 out:

	return result;
}

/* smb_receive's preconditions also apply here. */
static int
smb_receive_trans2 (
	struct smb_server *	server,
	int					command,
	int					sock_fd,
	int *				data_len_ptr,
	int *				param_len_ptr,
	char **				data_ptr,
	char **				param_ptr,
	int *				error_ptr)
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

	ASSERT( error_ptr != NULL );

	/* Careful: any of the "pass by reference" parameters may be NULL. */
	if(data_len_ptr != NULL)
		(*data_len_ptr) = 0;

	if(param_len_ptr != NULL)
		(*param_len_ptr) = 0;

	if(param_ptr != NULL)
		(*param_ptr) = NULL;

	if(data_ptr != NULL)
		(*data_ptr) = NULL;

	result = smb_receive (server, command, sock_fd, NULL, 0, error_ptr);
	if (result < 0)
		goto out;

	/* Is an error condition set? The caller is responsible
	 * for dealing with the error.
	 */
	if (server->rcls != 0)
		goto out;

	/* parse out the lengths */
	total_data = WVAL (inbuf, smb_tdrcnt);
	total_param = WVAL (inbuf, smb_tprcnt);

	if ((total_data > server->max_recv) || (total_param > server->max_recv))
	{
		LOG (("data/param too long\n"));

		(*error_ptr) = error_data_exceeds_buffer_size;

		result = -1;
		goto out;
	}

	/* Allocate it, but only if there is something to allocate
	 * in the first place.
	 */
	if(total_data > 0)
	{
		data = malloc (total_data);
		if (data == NULL)
		{
			LOG (("could not alloc data area\n"));

			(*error_ptr) = ENOMEM;

			result = -1;
			goto out;
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
			LOG (("could not alloc param area\n"));

			(*error_ptr) = ENOMEM;

			result = -1;
			goto out;
		}
	}

	LOG (("total_data/total_param: %ld/%ld\n", total_data, total_param));

	param_len = 0;
	data_len = 0;

	while (TRUE)
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
			LOG (("invalid parameters\n"));

			(*error_ptr) = error_invalid_parameter_size;

			result = -1;
			goto out;
		}

		if(param != NULL)
			memcpy (param + parameter_displacement, smb_base (inbuf) + parameter_offset, parameter_count);

		param_len += parameter_count;

		if (data_displacement + data_count > total_data)
		{
			LOG (("invalid data block\n"));

			(*error_ptr) = error_invalid_parameter_size;

			result = -1;
			goto out;
		}

		if(data != NULL)
			memcpy (data + data_displacement, smb_base (inbuf) + data_offset, data_count);

		data_len += data_count;

		LOG (("data count/parameter count: %ld/%ld\n", data_count, parameter_count));

		/* parse out the total lengths again - they can shrink! */
		if (total_data_count > total_data || total_parameter_count > total_param)
		{
			LOG (("data/params grew!\n"));

			(*error_ptr) = error_data_exceeds_buffer_size;

			result = -1;
			goto out;
		}

		total_data = total_data_count;
		total_param = total_parameter_count;

		if (total_data <= data_len && total_param <= param_len)
			break;

		result = smb_receive (server, command, sock_fd, NULL, 0, error_ptr);
		if (result < 0)
			goto out;

		if (server->rcls != 0)
		{
			(*error_ptr) = error_check_smb_error;

			result = -1;
			goto out;
		}
	}

	if(param_ptr != NULL && param_len_ptr != NULL)
	{
		(*param_ptr) = param;
		(*param_len_ptr) = param_len;
		param = NULL;
	}

	if(data_ptr != NULL && data_len_ptr != NULL)
	{
		(*data_ptr) = data;
		(*data_len_ptr) = data_len;
		data = NULL;
	}

	result = 0;

 out:

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

	server->state = CONN_INVALID;
}

int
smb_connect (struct smb_server *server, int * error_ptr)
{
	int enabled = TRUE;
	int result;

	ASSERT( server != NULL );
	ASSERT( error_ptr != NULL );

	if(server->mount_data.fd < 0)
	{
		result = socket (AF_INET, SOCK_STREAM, 0);
		if (result < 0)
		{
			server->state = CONN_INVALID;

			(*error_ptr) = errno;

			goto out;
		}

		server->mount_data.fd = result;
	}

	LOG(("connecting to server %s\n", Inet_NtoA(server->mount_data.addr.sin_addr.s_addr)));

	/* Wait a certain time period for the connection attempt to succeed? */
	if(server->timeout > 0)
	{
		int non_blocking_io;
		struct timeval tv;
		fd_set write_fds;

		/* Switch the socket into non-blocking mode, so that we
		 * may start the connection attempt and wait for it to
		 * either succeed or fail.
		 */
		non_blocking_io = TRUE;

		result = IoctlSocket(server->mount_data.fd, FIONBIO, &non_blocking_io);
		if(result < 0)
		{
			server->state = CONN_INVALID;

			(*error_ptr) = errno;

			goto out;
		}

		FD_ZERO(&write_fds);
		FD_SET(server->mount_data.fd,&write_fds);

		memset(&tv,0,sizeof(tv));

		tv.tv_secs = server->timeout;

		/* Try to establish the connection and don't hang around until
		 * it either succeeds or fails.
		 */
		connect (server->mount_data.fd, (struct sockaddr *)&server->mount_data.addr, sizeof(struct sockaddr_in));

		LOG(("will wait for up to %ld seconds for connection attempt to succeed\n",server->timeout));

		/* Wait for the connection status to change (success/failure), or until
		 * the timeout has elapsed.
		 */
		result = WaitSelect(server->mount_data.fd+1, NULL, &write_fds, NULL, &tv, NULL);

		/* Connection status is known? */
		if (result == 1)
		{
			socklen_t len;
			int error;

			error = 0;
			len = sizeof(error);

			/* Check if it failed or succeeded. */
			if(getsockopt(server->mount_data.fd,SOL_SOCKET,SO_ERROR,&error,&len) == 0)
			{
				/* Connection established? */
				if(error == 0)
				{
					result = 0;
				}
				/* Connection could not be made. */
				else
				{
					(*error_ptr) = errno;

					result = -1;
				}
			}
			/* Well, that could happen, too. */
			else
			{
				(*error_ptr) = errno;
				result = -1;
			}
		}
		/* Connection attempt timed out? */
		else if (result == 0)
		{
			(*error_ptr) = EWOULDBLOCK;
			result = -1;
		}
		/* Well, that could happen, too. */
		else /* if (result < 0) */
		{
			(*error_ptr) = errno;
		}

		/* Switch the socket back into blocking mode. */
		non_blocking_io = FALSE;
		IoctlSocket(server->mount_data.fd, FIONBIO, &non_blocking_io);

		if(result < 0)
		{
			server->state = CONN_INVALID;

			goto out;
		}
	}
	/* Wait almost indefinitely for the connection to
	 * be made.
	 */
	else
	{
		result = connect (server->mount_data.fd, (struct sockaddr *)&server->mount_data.addr, sizeof(struct sockaddr_in));
		if(result < 0)
		{
			server->state = CONN_INVALID;

			(*error_ptr) = errno;

			goto out;
		}
	}

	/* Enable socket keepalives, for good measure. */
	setsockopt(server->mount_data.fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));

	/* Configure the send/receive timeout (in seconds)? */
	if(server->timeout > 0)
	{
		struct timeval tv;

		memset(&tv,0,sizeof(tv));

		tv.tv_secs = server->timeout;

		setsockopt(server->mount_data.fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
		setsockopt(server->mount_data.fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	}

 out:

	return(result);
}

/* If there was a network error, or data was left unread,
 * the best option is to the close server connection and
 * reopen it again.
 *
 * Here's where we decide whether closing the connection
 * makes sense, and then close it if necessary.
 */
void
smb_check_server_connection(struct smb_server *server, int error)
{
	if(server->state == CONN_VALID)
	{
		int close_connection;

		switch(error)
		{
			case error_end_of_file:
			case error_invalid_netbios_session:
			case error_message_exceeds_buffer_size:
			case error_invalid_buffer_format:
			case error_data_exceeds_buffer_size:
			case error_invalid_parameter_size:
			case error_server_setup_incomplete:
			case error_server_connection_invalid:
			case error_smb_message_signature_missing:
			case error_smb_message_too_short:
			case error_smb_message_invalid_command:
			case error_smb_message_invalid_word_count:
			case error_smb_message_invalid_byte_count:

				close_connection = TRUE;
				break;

			default:

				close_connection = (error < error_end_of_file);
				break;
		}

		if(close_connection)
		{
			/* Stop means stop: EINTR is equivalent to Ctrl+C */
			if(error == EINTR)
				server->dont_retry = TRUE;

			smb_invalidate_all_inodes (server);

			SHOWMSG("closing the server connection.");
			smb_release(server);
		}
	}
}

/* Returns number of bytes received (>= 0) or a negative value in
 * case of error.
 */
int
smb_request (struct smb_server *server, int command, void * input_payload, const void * output_payload, int payload_size, int * error_ptr)
{
	unsigned char *buffer = server->transmit_buffer;
	int sock_fd = server->mount_data.fd;
	int len, result;

	ASSERT( error_ptr != NULL );

	if ((sock_fd < 0) || (buffer == NULL))
	{
		LOG (("Bad server!\n"));

		(*error_ptr) = error_server_setup_incomplete;

		result = -1;
		goto out;
	}

	if (server->state != CONN_VALID)
	{
		LOG (("Connection state is invalid\n"));

		(*error_ptr) = error_server_connection_invalid;

		result = -1;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	/* If there is a separate payload, only send the header
	 * here and take care of the payload later.
	 */
	if(output_payload != NULL && payload_size > 0)
	{
		ASSERT( payload_size < smb_len(buffer) );
		ASSERT( len > payload_size );

		len -= payload_size;
	}

	LOG (("len = %ld, cmd = 0x%lx, input_payload=0x%08lx, output_payload=0x%08lx, payload_size=%ld\n", len, buffer[8], input_payload, output_payload, payload_size));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,&buffer[NETBIOS_HEADER_SIZE],len);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	result = send (sock_fd, (void *) buffer, len, 0);
	if (result < 0)
	{
		LOG(("send() for %ld bytes failed (errno=%ld)\n", len, errno));

		(*error_ptr) = errno;

		goto out;
	}

	if(output_payload != NULL && payload_size > 0)
	{
		result = send (sock_fd, (void *)output_payload, payload_size, 0);
		if (result < 0)
		{
			LOG(("payload send() for %ld bytes failed (errno=%ld)\n", payload_size, errno));

			(*error_ptr) = errno;

			goto out;
		}
	}

	result = smb_receive (server, command, sock_fd, input_payload, payload_size, error_ptr);

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	LOG (("result = %ld\n", result));

	return (result);
}

/* This is not really a trans2 request, we assume that you only have
 * one packet to send.
 */
int
smb_trans2_request (struct smb_server *server, int command, int *data_len, int *param_len, char **data, char **param, int * error_ptr)
{
	unsigned char *buffer = server->transmit_buffer;
	int sock_fd = server->mount_data.fd;
	int len, result;

	ASSERT( error_ptr != NULL );

	if (server->state != CONN_VALID)
	{
		LOG (("Connection state is invalid\n"));

		(*error_ptr) = error_server_connection_invalid;

		result = -1;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	LOG (("len = %ld cmd = 0x%02lx\n", len, buffer[8]));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,NULL,0);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	result = send (sock_fd, (void *) buffer, len, 0);
	if (result < 0)
	{
		LOG(("send() for %ld bytes failed (errno=%ld)\n", len, errno));

		(*error_ptr) = errno;
		goto out;
	}

	result = smb_receive_trans2 (server, command, sock_fd, data_len, param_len, data, param, error_ptr);

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	LOG (("result = %ld\n", result));

	return result;
}
