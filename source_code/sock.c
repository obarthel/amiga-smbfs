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

static INLINE int
smb_len (const byte * packet)
{
	/* This returns the payload length stored in the NetBIOS session header. */
	return (((int)(packet[1] & 0x1)) << 16) | (((int)packet[2]) << 8) | (packet[3]);
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

/*****************************************************************************/

/* Attempt to receive all the incoming data, even if recv() returns only
 * parts of the total number of bytes requested. Returns the number of bytes
 * read or, in case of error, a negative number.
 */
static INLINE int
receive_all(int fd, void * _data, int len)
{
	char * data = _data;
	int result = 0;
	int n;

	ASSERT( data != NULL || len == 0 );

	for(;;)
	{
		PROFILE_OFF();

		n = recv(fd, data, len, 0);

		PROFILE_ON();

		if(n < 0)
		{
			result = -1;
			break;
		}

		result += n;

		len -= n;

		/* Stop as soon as all the requested data has been
		 * read, or there is no more data to be read (n == 0).
		 */
		if(len == 0 || n == 0)
			break;

		data += n;
	}

	return(result);
}

/*****************************************************************************/

/* Attempt to transmit all the incoming data, even if send() returns only
 * parts of the total number of bytes to be sent. Returns the total number of
 * bytes transmitted or, in case of error, a negative number.
 * 
 * send() is documented to not necessarily transport as much data as
 * requested, just like recv(), so we just play it safe here.
 */
static INLINE int
send_all(int fd, const void * _data, int len)
{
	const char * data = _data;
	int result = 0;
	int n;

	ASSERT( data != NULL || len == 0 );

	while(len > 0)
	{
		PROFILE_OFF();

		n = send(fd, (void *)data, len, 0);

		PROFILE_ON();

		if(n < 0)
		{
			result = -1;
			break;
		}

		result += n;

		data += n;

		len -= n;
	}

	return(result);
}

/*****************************************************************************/

/* Read the next NetBIOS frame and discard it. The primary purpose
 * of this function is to receive and ignore NetBIOS "keep alive"
 * messages.
 */
int
smb_discard_netbios_frames(struct smb_server *server, int sock_fd, int * error_ptr)
{
	unsigned char netbios_session_buf[NETBIOS_HEADER_SIZE];
	int netbios_session_payload_size;
	int result;

	ENTER();

	ASSERT( server != NULL );
	ASSERT( error_ptr != NULL );

	/* Read the NetBIOS session header (rfc-1002, section 4.3.1) */
	result = receive_all (sock_fd, netbios_session_buf, NETBIOS_HEADER_SIZE);
	if (result < 0)
	{
		(*error_ptr) = errno;

		D(("recv error = %ld", (*error_ptr)));
		goto out;
	}

	if (result < NETBIOS_HEADER_SIZE)
	{
		D(("expected %ld bytes, got %ld", NETBIOS_HEADER_SIZE, result));

		(*error_ptr) = error_end_of_file;

		result = -1;
		goto out;
	}

	/* Check the session type. */
	switch (netbios_session_buf[0])
	{
		/* 0x00 == session message */
		case 0x00:

			SHOWMSG("Got session message");
			break;

		/* 0x85 == session keepalive */
		case 0x85:

			SHOWMSG("Got session keepalive");
			break;

		/* 0x81 == session request */
		/* 0x82 == positive session response */
		/* 0x83 == negative session response */
		/* 0x84 == retarget session response */
		default:

			/* The session setup may need to know about the
			 * NetBIOS session response, but for any command
			 * these message types are invalid.
			 */
			D(("Invalid session header type 0x%02lx", netbios_session_buf[0]));

			(*error_ptr) = error_invalid_netbios_session;

			result = -1;
			goto out;
	}

	netbios_session_payload_size = (int)smb_len(netbios_session_buf);
	SHOWVALUE(netbios_session_payload_size);

	if(netbios_session_payload_size > 0)
	{
		/* The length in the NetBIOS header is the raw data length (17 bits) */
		if (netbios_session_payload_size > server->transmit_buffer_allocation_size)
		{
			D(("Received length (%ld) > max_xmit (%ld)!", netbios_session_payload_size, server->transmit_buffer_allocation_size));

			(*error_ptr) = error_message_exceeds_buffer_size;

			result = -1;
			goto out;
		}

		result = receive_all (sock_fd, server->transmit_buffer, netbios_session_payload_size);
		if (result < 0)
		{
			(*error_ptr) = errno;

			D(("recv error = %ld", (*error_ptr)));
			goto out;
		}
	}

 out:

	RETURN(result);
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
	unsigned char netbios_session_buf[NETBIOS_HEADER_SIZE];
	int netbios_session_payload_size = 0;
	int len, result;

	ASSERT( server != NULL );
	ASSERT( error_ptr != NULL );

	PROFILE_PUSH("SMB receive raw header");

	/* We need to read the NetBIOS session header before we can move
	 * on and read the SMB data. Because the NetBIOS session header
	 * may be a keepalive message or something else we can safely
	 * ignore, we will retry reading the header until we get to the
	 * point where it is safe to read the SMB data.
	 */
	while(TRUE)
	{
		server->rcls	= 0;
		server->err		= 0;

		PROFILE_PUSH("SMB receive raw header: receive_all()");

		/* Read the NetBIOS session header (rfc-1002, section 4.3.1) */
		result = receive_all (sock_fd, netbios_session_buf, NETBIOS_HEADER_SIZE);

		PROFILE_POP("SMB receive raw header: receive_all()");

		if (result < 0)
		{
			(*error_ptr) = errno;

			D(("recv error = %ld", (*error_ptr)));

			PROFILE_POP("SMB receive raw header");

			goto out;
		}

		if (result < NETBIOS_HEADER_SIZE)
		{
			D(("expected %ld bytes, got %ld for the NetBIOS header", NETBIOS_HEADER_SIZE, result));

			(*error_ptr) = error_end_of_file;

			result = -1;

			PROFILE_POP("SMB receive raw header");

			goto out;
		}

		netbios_session_payload_size = (int)smb_len(netbios_session_buf);
		SHOWVALUE(netbios_session_payload_size);

		#if defined(DUMP_SMB)
		{
			if(command != 0 && netbios_session_buf[0] != 0x00 && netbios_session_payload_size > 0)
			{
				unsigned char netbios_session_payload[256];

				/* We only want to show what's in the first few
				 * bytes of a session packet. Since we only support
				 * two session packet types (session message and
				 * session keep alive) we will abort processing
				 * anyway so it doesn't matter if we ignore any
				 * data beyond the first 256 bytes.
				 */
				if(netbios_session_payload_size > (int)sizeof(netbios_session_payload))
					netbios_session_payload_size = sizeof(netbios_session_payload);

				result = receive_all (sock_fd, netbios_session_payload, netbios_session_payload_size);
				if (result < 0)
				{
					(*error_ptr) = errno;

					D(("recv error = %ld", (*error_ptr)));

					PROFILE_POP("SMB receive raw header");

					goto out;
				}

				if(result < netbios_session_payload_size)
				{
					D(("result (%ld) < %ld", result, netbios_session_payload_size));

					(*error_ptr) = error_end_of_file;

					result = -1;

					PROFILE_POP("SMB receive raw header");

					goto out;
				}

				dump_netbios_header(__FILE__,__LINE__,netbios_session_buf,netbios_session_payload,netbios_session_payload_size);
			}
			else
			{
				dump_netbios_header(__FILE__,__LINE__,netbios_session_buf,NULL,0);
			}
		}
		#endif /* defined(DUMP_SMB) */

		/* Is this a session keepalive message? If so,
		 * read the next frame.
		 */
		if (netbios_session_buf[0] == 0x85)
		{
			SHOWMSG("Got SESSION KEEP ALIVE");
			continue;
		}
		/* Is this a regular session message? This is what
		 * we came for.
		 */
		else if (netbios_session_buf[0] == 0x00)
		{
			break;
		}

		/* Check the session type again, looking for
		 * anything peculiar.
		 */
		switch (netbios_session_buf[0])
		{
			/* 0x00 == session message */
			case 0x00:

				/* This is what we came for. */
				break;

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
					D(("Invalid session header type 0x%02lx", netbios_session_buf[0]));

					(*error_ptr) = error_invalid_netbios_session;

					result = -1;

					PROFILE_POP("SMB receive raw header");

					goto out;
				}

				/* Ignore this message type. */
				break;
		}

		break;
	}

	PROFILE_POP("SMB receive raw header");

	/* The length in the NetBIOS header is the raw data length (17 bits) */
	len = netbios_session_payload_size;
	if (len > max_raw_length)
	{
		D(("Received length (%ld) > max_xmit (%ld)!", len, max_raw_length));

		(*error_ptr) = error_message_exceeds_buffer_size;

		result = -1;
		goto out;
	}

	/* Prepend the NetBIOS header to what is read? */
	if (want_header)
	{
		ASSERT( target != NULL );

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
	 *
	 * Note that this optimization may still not take effect because the
	 * amount of data expected to be received can be so small that it
	 * may make little sense to break up reception into two separate
	 * recv() calls.
	 */
	if(input_payload != NULL)
	{
		/* Receive SMB message header and payload separately? */
		if(len > server->smb_read_threshold)
		{
			int num_bytes_received = 0;

			SHOWMSG("receiving SMB message and payload separately");

			D(("input_payload=0x%08lx, payload_size=%ld", (unsigned long)input_payload, input_payload_size));

			if(command == SMBreadX)
			{
				int data_length;
				int data_offset;

				PROFILE_PUSH("SMBreadX");

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

				D(("SMBreadX: reading the first %ld bytes", 59));

				ASSERT( target != NULL );

				result = receive_all (sock_fd, target, 59);
				if (result < 0)
				{
					(*error_ptr) = errno;

					D(("recv error = %ld", (*error_ptr)));

					PROFILE_POP("SMBreadX");

					goto out;
				}

				num_bytes_received += result;

				ASSERT( num_bytes_received == 59 );

				/* End of file reached? */
				if(num_bytes_received < 59)
				{
					/* End of file */
					SHOWMSG("EOF");

					(*error_ptr) = error_end_of_file;

					result = -1;

					PROFILE_POP("SMBreadX");

					goto out;
				}

				data_offset = WVAL(target, 45);

				SHOWVALUE(data_offset);

				/* Skip the padding bytes, if any. */
				if(data_offset > 59)
				{
					D(("skipping %ld padding bytes", data_offset - 59));

					result = receive_all (sock_fd, target + 59, data_offset - 59);
					if (result < 0)
					{
						(*error_ptr) = errno;

						D(("recv error = %ld", (*error_ptr)));

						PROFILE_POP("SMBreadX");

						goto out;
					}

					/* End of file reached? */
					if(result < data_offset - 59)
					{
						/* End of file */
						SHOWMSG("EOF");

						(*error_ptr) = error_end_of_file;

						result = -1;

						PROFILE_POP("SMBreadX");

						goto out;
					}

					num_bytes_received += result;
				}

				data_length = WVAL(target, 43);

				SHOWVALUE(data_length);

				ASSERT( data_length <= input_payload_size );

				result = receive_all (sock_fd, input_payload, data_length);
				if (result < 0)
				{
					(*error_ptr) = errno;

					D(("recv error = %ld", (*error_ptr)));

					PROFILE_POP("SMBreadX");

					goto out;
				}

				if(result < data_length)
				{
					/* End of file */
					SHOWMSG("EOF");

					(*error_ptr) = error_end_of_file;

					result = -1;

					PROFILE_POP("SMBreadX");

					goto out;
				}

				num_bytes_received += result;

				/* This should never happen, but then we better make sure to
				 * read the entire message.
				 */
				if(num_bytes_received < len)
				{
					D(("reading the remaining %ld bytes; this should never happen", len - num_bytes_received ));

					result = receive_all (sock_fd, &target[num_bytes_received], len - num_bytes_received);
					if (result < 0)
					{
						(*error_ptr) = errno;

						D(("recv error = %ld", (*error_ptr)));

						PROFILE_POP("SMBreadX");

						goto out;
					}

					if(result < len - num_bytes_received)
					{
						/* End of file */
						SHOWMSG("EOF");

						(*error_ptr) = error_end_of_file;

						result = -1;

						PROFILE_POP("SMBreadX");

						goto out;
					}
				}

				PROFILE_POP("SMBreadX");
			}
			else
			{
				int count_of_bytes_returned;
				int count_of_bytes_to_read;
				int buffer_format;

				PROFILE_PUSH("SMBread");

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

				D(("SMBread: reading the first %ld bytes", 48));

				ASSERT( target != NULL );

				result = receive_all (sock_fd, target, 48);
				if (result < 0)
				{
					(*error_ptr) = errno;

					D(("recv error = %ld", (*error_ptr)));

					PROFILE_POP("SMBread");

					goto out;
				}

				num_bytes_received += result;

				ASSERT( num_bytes_received == 48 );

				/* End of file reached? */
				if(num_bytes_received < 48)
				{
					/* End of file */
					SHOWMSG("EOF");

					(*error_ptr) = error_end_of_file;

					result = -1;

					PROFILE_POP("SMBread");

					goto out;
				}

				/* So we read the header. Now we need to figure out if the
				 * data is in the expected format, and how many bytes are
				 * waiting to be read.
				 */

				/* The buffer format must be 1. */
				buffer_format = BVAL(target, 45);

				D(("buffer format = %ld, should be %ld", buffer_format, 1));

				if(buffer_format != 1)
				{
					D(("buffer format %ld not supported", buffer_format));

					(*error_ptr) = error_invalid_buffer_format;

					result = -1;

					PROFILE_POP("SMBread");

					goto out;
				}

				count_of_bytes_returned = WVAL(target, 33);
				count_of_bytes_to_read = WVAL(target, 46);

				/* That should never be more data than the read buffer may hold. */
				ASSERT( count_of_bytes_to_read <= input_payload_size );
				ASSERT( count_of_bytes_to_read <= count_of_bytes_returned );
				ASSERT( count_of_bytes_returned <= input_payload_size );

				D(("count of bytes to read = %ld, should be <= %ld", count_of_bytes_to_read, input_payload_size));

				if(count_of_bytes_returned > input_payload_size)
				{
					SHOWMSG("this is too much data");

					(*error_ptr) = error_message_exceeds_buffer_size;

					result = -1;

					PROFILE_POP("SMBread");

					goto out;
				}

				result = receive_all (sock_fd, input_payload, count_of_bytes_to_read);
				if (result < 0)
				{
					(*error_ptr) = errno;

					D(("recv error = %ld", (*error_ptr)));

					PROFILE_POP("SMBread");

					goto out;
				}

				if(result < count_of_bytes_to_read)
				{
					/* End of file */
					SHOWMSG("EOF");

					(*error_ptr) = error_end_of_file;

					result = -1;

					PROFILE_POP("SMBread");

					goto out;
				}

				num_bytes_received += result;

				ASSERT( count_of_bytes_to_read == count_of_bytes_returned );

				if(count_of_bytes_to_read < count_of_bytes_returned)
				{
					D(("fewer data available than should be delivered; setting the remainder (%ld bytes) to 0.", count_of_bytes_returned - count_of_bytes_to_read));

					memset(&input_payload[count_of_bytes_to_read],0,count_of_bytes_returned - count_of_bytes_to_read);
				}

				/* This should never happen, but then we better make sure to
				 * read the entire message.
				 */
				if(num_bytes_received < len)
				{
					D(("reading the remaining %ld bytes; this should never happen", len - num_bytes_received ));

					result = receive_all (sock_fd, &target[num_bytes_received], len - num_bytes_received);
					if (result < 0)
					{
						(*error_ptr) = errno;

						D(("recv error = %ld", (*error_ptr)));

						PROFILE_POP("SMBread");

						goto out;
					}

					if(result < len - num_bytes_received)
					{
						/* End of file */
						SHOWMSG("EOF");

						(*error_ptr) = error_end_of_file;

						result = -1;

						PROFILE_POP("SMBread");

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

				PROFILE_POP("SMBread");
			}

			result = num_bytes_received;
		}
		/* No, read both as a single chunk through recv() and pick
		 * the SMB message header and its payload apart later. This
		 * is intended to improve small read operation performance
		 * for which two separate recv() operations may introduce
		 * additional delays in processing.
		 */
		else
		{
			PROFILE_PUSH("SMB read full");

			SHOWMSG("receiving SMB message and payload in one chunk");

			ASSERT( target != NULL );

			result = receive_all (sock_fd, target, len);
			if (result < 0)
			{
				(*error_ptr) = errno;

				D(("recv error = %ld", (*error_ptr)));

				PROFILE_POP("SMB read full");

				goto out;
			}

			if(result < len)
			{
				/* End of file */
				SHOWMSG("EOF");

				(*error_ptr) = error_end_of_file;

				result = -1;

				PROFILE_POP("SMB read full");

				goto out;
			}

			#if defined(DUMP_SMB)
			{
				/* If want_header==0 then this is the data returned by SMB_COM_READ_RAW. */
				dump_smb(__FILE__,__LINE__,!want_header,target,result,smb_packet_to_consumer,server->max_recv);
			}
			#endif /* defined(DUMP_SMB) */

			if(command == SMBreadX)
			{
				int data_length;
				int data_offset;

				data_offset = WVAL(target, 45);
				SHOWVALUE(data_offset);

				data_length = WVAL(target, 43);
				SHOWVALUE(data_length);

				ASSERT( data_offset < len );
				ASSERT( data_offset + data_length <= len );
				ASSERT( data_length <= input_payload_size );

				memcpy(input_payload, &target[data_offset], data_length);
			}
			else
			{
				int count_of_bytes_returned;
				int count_of_bytes_to_read;
				int buffer_format;

				ASSERT( command == SMBread );

				/* The buffer format must be 1. */
				buffer_format = BVAL(target, 45);

				D(("buffer format = %ld, should be %ld", buffer_format, 1));

				if(buffer_format != 1)
				{
					D(("buffer format %ld not supported", buffer_format));

					(*error_ptr) = error_invalid_buffer_format;

					result = -1;

					PROFILE_POP("SMB read full");

					goto out;
				}

				count_of_bytes_returned = WVAL(target, 33);
				count_of_bytes_to_read = WVAL(target, 46);

				/* That should never be more data than the read buffer may hold. */
				ASSERT( count_of_bytes_to_read <= input_payload_size );
				ASSERT( count_of_bytes_to_read <= count_of_bytes_returned );
				ASSERT( count_of_bytes_returned <= input_payload_size );

				D(("count of bytes to read = %ld, should be <= %ld", count_of_bytes_to_read, input_payload_size));

				if(count_of_bytes_returned > input_payload_size)
				{
					SHOWMSG("this is too much data");

					(*error_ptr) = error_message_exceeds_buffer_size;

					result = -1;

					PROFILE_POP("SMB read full");

					goto out;
				}

				memcpy(input_payload, &target[48], count_of_bytes_to_read);

				ASSERT( count_of_bytes_to_read == count_of_bytes_returned );

				if(count_of_bytes_to_read < count_of_bytes_returned)
				{
					D(("fewer data available than should be delivered; setting the remainder (%ld bytes) to 0.", count_of_bytes_returned - count_of_bytes_to_read));

					memset(&input_payload[count_of_bytes_to_read],0,count_of_bytes_returned - count_of_bytes_to_read);
				}
			}

			PROFILE_POP("SMB read full");
		}
	}
	else
	{
		PROFILE_PUSH("SMB read single buffer");

		ASSERT( target != NULL );

		result = receive_all (sock_fd, target, len);
		if (result < 0)
		{
			(*error_ptr) = errno;

			D(("recv error = %ld", (*error_ptr)));

			PROFILE_POP("SMB read single buffer");

			goto out;
		}

		if(result < len)
		{
			/* End of file */
			SHOWMSG("EOF");

			(*error_ptr) = error_end_of_file;

			result = -1;

			PROFILE_POP("SMB read single buffer");

			goto out;
		}

		#if defined(DUMP_SMB)
		{
			/* If want_header==0 then this is the data returned by SMB_COM_READ_RAW. */
			dump_smb(__FILE__,__LINE__,!want_header,target,result,smb_packet_to_consumer,server->max_recv);
		}
		#endif /* defined(DUMP_SMB) */

		PROFILE_POP("SMB read single buffer");
	}

 out:

	return result;
}

static int
smb_receive (
	struct smb_server *server,
	int command,
	int sock_fd,
	void * input_payload,
	int payload_size,
	int * error_ptr)
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
		D(("receive error: %ld", (*error_ptr)));
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
		SHOWMSG("data/param too long");

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
			SHOWMSG("could not alloc data area");

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
			SHOWMSG("could not alloc param area");

			(*error_ptr) = ENOMEM;

			result = -1;
			goto out;
		}
	}

	D(("total_data/total_param: %ld/%ld", total_data, total_param));

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
			SHOWMSG("invalid parameters");

			(*error_ptr) = error_invalid_parameter_size;

			result = -1;
			goto out;
		}

		if(param != NULL)
			memcpy (param + parameter_displacement, smb_base (inbuf) + parameter_offset, parameter_count);

		param_len += parameter_count;

		if (data_displacement + data_count > total_data)
		{
			SHOWMSG("invalid data block");

			(*error_ptr) = error_invalid_parameter_size;

			result = -1;
			goto out;
		}

		if(data != NULL)
			memcpy (data + data_displacement, smb_base (inbuf) + data_offset, data_count);

		data_len += data_count;

		D(("data count/parameter count: %ld/%ld", data_count, parameter_count));

		/* parse out the total lengths again - they can shrink! */
		if (total_data_count > total_data || total_parameter_count > total_param)
		{
			SHOWMSG("data/params grew!");

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
		PROFILE_OFF();

		CloseSocket (server->mount_data.fd);

		PROFILE_ON();

		server->mount_data.fd = -1;
	}

	server->state = CONN_INVALID;
}

int
smb_connect (struct smb_server *server, int * error_ptr)
{
	int enabled = TRUE;
	int result;

	PROFILE_OFF();

	ASSERT( server != NULL );
	ASSERT( error_ptr != NULL );

	if(server->mount_data.fd < 0)
	{
		SHOWMSG("network socket needs to be opened");

		result = socket (AF_INET, SOCK_STREAM, 0);
		if (result < 0)
		{
			server->state = CONN_INVALID;

			(*error_ptr) = errno;

			goto out;
		}

		server->mount_data.fd = result;
	}

	D(("connecting to server %s:%ld with socket %ld",
		Inet_NtoA(server->mount_data.addr.sin_addr.s_addr),
		ntohs(server->mount_data.addr.sin_port),
		server->mount_data.fd));

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

		D(("will wait for up to %ld seconds for connection attempt to succeed",server->timeout));

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
					D(("connection could not be established (error=%ld)",errno));

					(*error_ptr) = errno;

					result = -1;
				}
			}
			/* Well, that could happen, too. */
			else
			{
				D(("connection could not be established (error=%ld)",errno));

				(*error_ptr) = errno;
				result = -1;
			}
		}
		/* Connection attempt timed out? */
		else if (result == 0)
		{
			SHOWMSG("connection could not be established (timeout)");

			(*error_ptr) = EWOULDBLOCK;
			result = -1;
		}
		/* Well, that could happen, too. */
		else /* if (result < 0) */
		{
			D(("connection could not be established (error=%ld)",errno));

			(*error_ptr) = errno;
		}

		/* Switch the socket back into blocking mode. */
		non_blocking_io = FALSE;
		IoctlSocket(server->mount_data.fd, FIONBIO, &non_blocking_io);

		if(result < 0)
		{
			server->state = CONN_INVALID;

			SHOWMSG("connection is invalid.");
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
			D(("connect() has failed (errno=%ld)",errno));

			server->state = CONN_INVALID;

			(*error_ptr) = errno;

			goto out;
		}
	}

	/* Enable socket keepalives, for good measure. */
	setsockopt(server->mount_data.fd, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled));

	/* Disable the Nagle algorithm for send() operations, causing the
	 * data to be sent as soon as possible, rather than being subjected
	 * to traffic control/smoothing?
	 */
	if(server->tcp_no_delay)
		setsockopt(server->mount_data.fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));

	/* Request specific socket receive/transmit buffer sizes? Note that
	 * this is a request, not a figure which the TCP/IP stack has to
	 * honour.
	 */
	if(server->socket_receive_buffer_size > 0)
		setsockopt(server->mount_data.fd, SOL_SOCKET, SO_RCVBUF, &server->socket_receive_buffer_size, sizeof(server->socket_receive_buffer_size));

	if(server->socket_send_buffer_size > 0)
		setsockopt(server->mount_data.fd, SOL_SOCKET, SO_SNDBUF, &server->socket_send_buffer_size, sizeof(server->socket_send_buffer_size));

	/* Configure the send/receive timeout (in seconds)? */
	if(server->timeout > 0)
	{
		struct timeval tv;

		memset(&tv,0,sizeof(tv));

		tv.tv_secs = server->timeout;

		D(("server timeout = %ld seconds", server->timeout));

		setsockopt(server->mount_data.fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
		setsockopt(server->mount_data.fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
	}
	else
	{
		SHOWMSG("no server read/write/connect timeout was set");
	}

 out:

	PROFILE_ON();

	return(result);
}

/* If there was a network error, or data was left unread,
 * the best option is to close the server connection and
 * reopen it again.
 *
 * Here's where we decide whether closing the connection
 * makes sense, and then close it if necessary.
 */
void
smb_check_server_connection(struct smb_server *server, int error)
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

		smba_invalidate_all_inodes (server->abstraction);

		SHOWMSG("closing the server connection.");
		smb_release(server);

		server->state = CONN_INVALID;
	}
}

/* Returns number of bytes received (>= 0) or a negative value in
 * case of error.
 */
int
smb_request (
	struct smb_server *server,
	int command,
	void * input_payload,
	const void * output_payload,
	int payload_size,
	int * error_ptr)
{
	unsigned char *buffer = server->transmit_buffer;
	int sock_fd = server->mount_data.fd;
	int len, result;

	ASSERT( error_ptr != NULL );

	if ((sock_fd < 0) || (buffer == NULL))
	{
		SHOWMSG("Bad server!");

		(*error_ptr) = error_server_setup_incomplete;

		result = -1;
		goto out;
	}

	if (server->state != CONN_VALID)
	{
		SHOWMSG("Connection state is invalid");

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

		/* Send SMB message header and payload separately? */
		if(len > server->smb_write_threshold)
		{
			SHOWMSG("sending SMB message and payload separately");

			len -= payload_size;
		}
		/* No, combine both into a single chunk which will be
		 * transmitted with a single send(). This is intended
		 * to improve small write operation performance for
		 * which two separate send() operations may not succeed
		 * in nudging the TCP/IP stack to transmit the data just
		 * yet (Nagle algorithm, etc.).
		 */
		else
		{
			SHOWMSG("sending SMB message and payload in one chunk");

			memcpy(&buffer[len - payload_size], output_payload, payload_size);

			output_payload = NULL;
			payload_size = 0;
		}
	}

	D(("len = %ld, cmd = 0x%lx, input_payload=0x%08lx, output_payload=0x%08lx, payload_size=%ld",
		len,
		buffer[8],
		(unsigned long)input_payload,
		(unsigned long)output_payload,
		payload_size));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,&buffer[NETBIOS_HEADER_SIZE],len);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	if(output_payload != NULL && payload_size > 0)
	{
		/* Use two send() calls for header and payload? */
		if(!server->scatter_gather)
		{
			SHOWMSG("using two send() calls");

			result = send_all (sock_fd, buffer, len);
			if (result < 0)
			{
				D(("send() for %ld bytes failed (errno=%ld)", len, errno));

				(*error_ptr) = errno;

				goto out;
			}

			result = send_all (sock_fd, output_payload, payload_size);
			if (result < 0)
			{
				D(("payload send() for %ld bytes failed (errno=%ld)", payload_size, errno));

				(*error_ptr) = errno;

				goto out;
			}
		}
		/* No, use sendmsg() to transmit both header and payload
		 * in one single step.
		 */
		else
		{
			struct msghdr msg;
			struct iovec iov[2];

			D(("using sendmsg() for %ld+%ld = %ld bytes", len, payload_size, len+payload_size));

			memset(&msg,0,sizeof(msg));

			msg.msg_iov		= iov;
			msg.msg_iovlen	= 2;

			iov[0].iov_base	= buffer;
			iov[0].iov_len	= len;

			iov[1].iov_base	= (void *)output_payload;
			iov[1].iov_len	= payload_size;

			PROFILE_OFF();

			result = sendmsg (sock_fd, &msg, 0);

			PROFILE_ON();

			if (result < 0)
			{
				D(("sendmsg() for %ld+%ld bytes failed (errno=%ld)", len, payload_size, errno));

				(*error_ptr) = errno;

				goto out;
			}
		}
	}
	else
	{
		result = send_all (sock_fd, buffer, len);
		if (result < 0)
		{
			D(("send() for %ld bytes failed (errno=%ld)", len, errno));

			(*error_ptr) = errno;

			goto out;
		}
	}

	result = smb_receive (server, command, sock_fd, input_payload, payload_size, error_ptr);

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	D(("result = %ld", result));

	return (result);
}

/* This is not really a trans2 request, we assume that you only have
 * one packet to send.
 */
int
smb_trans2_request (
	struct smb_server *server,
	int command,
	int *data_len,
	int *param_len,
	char **data,
	char **param,
	int * error_ptr)
{
	unsigned char *buffer = server->transmit_buffer;
	int sock_fd = server->mount_data.fd;
	int len, result;

	ASSERT( error_ptr != NULL );

	if (server->state != CONN_VALID)
	{
		SHOWMSG("Connection state is invalid");

		(*error_ptr) = error_server_connection_invalid;

		result = -1;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	D(("len = %ld cmd = 0x%02lx", len, buffer[8]));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,NULL,0);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	result = send_all (sock_fd, buffer, len);
	if (result < 0)
	{
		D(("send() for %ld bytes failed (errno=%ld)", len, errno));

		(*error_ptr) = errno;
		goto out;
	}

	result = smb_receive_trans2 (server, command, sock_fd, data_len, param_len, data, param, error_ptr);

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	D(("result = %ld", result));

	return result;
}

/* Perform the actual read operation for the SMBreadbraw command, for which
 * the transmit buffer has already been set up, ready to be used. This
 * function is called by smb_proc_read_raw().
 */
int
smb_request_read_raw (struct smb_server *server, unsigned char *target, int max_len, int * error_ptr)
{
	unsigned char *buffer = server->transmit_buffer;
	int sock_fd = server->mount_data.fd;
	int len, result;

	ASSERT( error_ptr != NULL );

	if (server->state != CONN_VALID)
	{
		SHOWMSG("Connection state is invalid");

		(*error_ptr) = error_server_connection_invalid;

		result = -1;
		goto out;
	}

	/* Length includes the NetBIOS session header (4 bytes), which
	 * is prepended to the packet to be sent.
	 */
	len = NETBIOS_HEADER_SIZE + smb_len (buffer);

	D(("len = %ld cmd = 0x%02lx", len, buffer[8]));
	D(("target=%lx, max_len=%ld", (unsigned int) target, max_len));
	D(("buffer=%lx, sock=%lx", (unsigned int) buffer, (unsigned int) sock_fd));

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,buffer,NULL,0);
	dump_smb(__FILE__,__LINE__,0,buffer+NETBIOS_HEADER_SIZE,len-NETBIOS_HEADER_SIZE,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	/* Request that data should be read in raw mode. */
	result = send_all (sock_fd, buffer, len);
	if (result < 0)
	{
		D(("send() for %ld bytes failed (errno=%ld)", len, errno));

		(*error_ptr) = errno;

		goto out;
	}

	/* Wait for the raw data to be sent by the server. */
	result = smb_receive_raw (server, SMBreadbraw, sock_fd, target, max_len, NULL, 0, FALSE, error_ptr);

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	D(("result = %ld", result));

	return result;
}

/* smb_request_write_raw assumes that the request SMBwriteBraw has been
 * completed successfully, so that we can send the raw data now.
 */
int
smb_request_write_raw (struct smb_server *server, unsigned const char *source, int length, int * error_ptr)
{
	byte nb_header[NETBIOS_HEADER_SIZE];
	int sock_fd = server->mount_data.fd;
	int result;

	if (server->state != CONN_VALID)
	{
		SHOWMSG("Connection state is invalid");

		(*error_ptr) = error_server_connection_invalid;

		result = -1;
		goto out;
	}

	ASSERT( length <= 65535 );

	/* Prepare the NetBIOS header, which in this case is
	 * providing the length of the data to follow it.
	 */
	smb_encode_smb_length (nb_header, length);

	#if defined(DUMP_SMB)
	dump_netbios_header(__FILE__,__LINE__,nb_header,NULL,0);
	dump_smb(__FILE__,__LINE__,0,source,length,smb_packet_from_consumer,server->max_recv);
	#endif /* defined(DUMP_SMB) */

	/* Use two send() calls to transmit header and data? */
	if(!server->scatter_gather)
	{
		SHOWMSG("using two send() calls");

		/* Send the NetBIOS header. */
		result = send_all (sock_fd, nb_header, NETBIOS_HEADER_SIZE);
		if(result < 0)
		{
			D(("send() for %ld bytes failed (errno=%ld)", NETBIOS_HEADER_SIZE, errno));

			(*error_ptr) = errno;

			goto out;
		}

		/* Now send the data to be written. */
		result = send_all (sock_fd, source, length);
		if(result < 0)
		{
			D(("send() for %ld bytes failed (errno=%ld)", length, errno));

			(*error_ptr) = errno;

			goto out;
		}
	}
	/* No, use sendmsg() to transmit header and data in
	 * one single step.
	 */
	else
	{
		struct msghdr msg;
		struct iovec iov[2];

		D(("using sendmsg() for %ld+%ld = %ld bytes", NETBIOS_HEADER_SIZE, length, NETBIOS_HEADER_SIZE+length));

		memset(&msg,0,sizeof(msg));

		msg.msg_iov		= iov;
		msg.msg_iovlen	= 2;

		iov[0].iov_base	= nb_header;
		iov[0].iov_len	= NETBIOS_HEADER_SIZE;

		iov[1].iov_base	= (void *)source;
		iov[1].iov_len	= length;

		PROFILE_OFF();

		result = sendmsg (sock_fd, &msg, 0);

		PROFILE_ON();

		if (result < 0)
		{
			D(("sendmsg() for %ld+%ld bytes failed (errno=%ld)", NETBIOS_HEADER_SIZE, length, errno));

			(*error_ptr) = errno;

			goto out;
		}
	}

	/* Wait for the server to respond. */
	if(!server->write_behind)
	{
		result = smb_receive (server, SMBwritebraw, sock_fd, NULL, 0, error_ptr);
		if(result < 0)
			goto out;
	}
	else
	{
		SHOWMSG("not waiting for server to respond");
	}

	result = length;

 out:

	if (result < 0)
		smb_check_server_connection(server,(*error_ptr));

	D(("result = %ld", result));

	return result;
}
