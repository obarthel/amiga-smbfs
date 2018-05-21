/*
 * :ts=4
 *
 * Name: smb_abstraction.c
 * Description: Smb abstraction layer.
 * Author: Christian Starkjohann <cs -at- hal -dot- kph -dot- tuwien -dot- ac -dot- at>
 * Date: 1996-12-31
 * Copyright: GNU-GPL
 *
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#include "smbfs.h"
#include "errors.h"

/*****************************************************************************/

#include <smb/smb_fs.h>
#include <smb/smb.h>
#include <smb/smbno.h>

/*****************************************************************************/

#define ATTR_CACHE_TIME		5	/* cache attributes for this time (seconds) */
#define DIR_CACHE_TIME		5	/* cache directories for this time (seconds) */
#define DIRCACHE_SIZE		170
#define DOS_PATHSEP			'\\'

/*****************************************************************************/

typedef struct dircache
{
	int					base;
	int					len;
	int					eof;		/* cache end is eof */
	ULONG				created_at;	/* for invalidation */
	struct smba_file *	cache_for;	/* owner of this cache */
	int					cache_size;
	struct smb_dirent	cache[1];
} dircache_t;

/* opaque structures for server and files: */
struct smba_server
{
	struct smb_server	server;
	struct MinList		open_files;
	dircache_t *		dircache;
	unsigned			supports_E:1;
	unsigned			supports_E_known:1;
};

struct smba_file
{
	struct MinNode			node;
	struct smba_server *	server;
	struct smb_dirent		dirent;
	ULONG					attr_time;		/* time when dirent was read */
	dircache_t *			dircache;		/* content cache for directories */
	unsigned				attr_dirty:1;	/* attribute cache is dirty */
	unsigned				is_valid:1;		/* server was down, entry removed, ... */
};

/*****************************************************************************/

#include "smb_abstraction.h"

/*****************************************************************************/

static void smba_cleanup_dircache(struct smba_server * server);
static int smba_setup_dircache (struct smba_server * server,int cache_size, int * error_ptr);

/*****************************************************************************/

static int
smba_connect (
	smba_connect_parameters_t *	p,
	in_addr_t					ip_addr,
	int							use_E,
	char *						workgroup_name,
	int							cache_size,
	int							max_transmit,
	int							timeout,
	int							opt_raw_smb,
	int							opt_write_behind,
	int							opt_prefer_write_raw,
	int							opt_disable_write_raw,
	int							opt_disable_read_raw,
	char *						opt_native_os,
	int *						error_ptr,
	int *						smb_error_class_ptr,
	int *						smb_error_ptr,
	smba_server_t **			smba_server_ptr)
{
	smba_server_t *res;
	struct smb_mount_data data;
	char hostname[MAXHOSTNAMELEN], *s;
	struct servent * servent;
	int result = -1;

	(*smba_server_ptr) = NULL;

	res = malloc (sizeof(*res));
	if(res == NULL)
	{
		ReportError("Not enough memory.");

		(*error_ptr) = ENOMEM;
		goto error_occured;
	}

	memset (res, 0, sizeof(*res));
	memset (&data, 0, sizeof (data));
	memset (hostname, 0, sizeof (hostname));

	/* Olaf (2012-12-10): force raw SMB over TCP rather than NetBIOS. */
	if(opt_raw_smb)
		res->server.raw_smb = TRUE;

	/* olsen (2016-04-20): Use write-behind with SMB_COM_WRITE_RAW. */
	if(opt_write_behind)
		res->server.write_behind = TRUE;

	/* olsen (2018-05-08): Always use SMB_COM_WRITE, even if SMB_COM_WRITE_RAW were possible. */
	if(opt_disable_write_raw)
	{
		res->server.disable_write_raw = TRUE;
	}
	else
	{
		/* olsen (2016-04-20): Prefer the use of SMB_COM_WRITE_RAW over SMB_COM_WRITE. */
		if(opt_prefer_write_raw)
			res->server.prefer_write_raw = TRUE;
	}

	/* olsen (2018-05-08): Always use SMB_COM_READ, even if SMB_COM_READ_RAW were possible. */
	if(opt_disable_read_raw)
		res->server.disable_read_raw = TRUE;

	/* olsen (2018-05-09): Timeout for send/receive operations in seconds. */
	res->server.timeout = timeout;

	/* olsen (2018-05-18): Override the "Native OS" name passed to the server. */
	res->server.native_os = opt_native_os;

	if(smba_setup_dircache (res,cache_size,error_ptr) < 0)
	{
		ReportError("Directory cache initialization failed (%ld, %s).",(*error_ptr),posix_strerror(*error_ptr));
		goto error_occured;
	}

	strlcpy(data.workgroup_name,workgroup_name,sizeof(data.workgroup_name));

	res->server.abstraction = res;

	gethostname (hostname, MAXHOSTNAMELEN);

	if ((s = strchr (hostname, '.')) != NULL)
		(*s) = '\0';

	data.addr.sin_family		= AF_INET;
	data.addr.sin_addr.s_addr	= ip_addr;

	if(res->server.raw_smb)
	{
		servent = getservbyname("microsoft-ds","tcp");
		if(servent != NULL)
			data.addr.sin_port = servent->s_port;
		else
			data.addr.sin_port = htons (445);
	}
	else
	{
		servent = getservbyname("netbios-ssn","tcp");
		if(servent != NULL)
			data.addr.sin_port = servent->s_port;
		else
			data.addr.sin_port = htons (139);
	}

	data.fd = socket (AF_INET, SOCK_STREAM, 0);
	if (data.fd < 0)
	{
		ReportError("socket() call failed (%ld, %s).", errno, posix_strerror(errno));

		(*error_ptr) = errno;
		goto error_occured;
	}

	strlcpy (data.service, p->service, sizeof(data.service));
	StringToUpper (data.service);
	strlcpy (data.username, p->username, sizeof(data.username));
	strlcpy (data.password, p->password, sizeof(data.password));

	data.given_max_xmit = max_transmit;

	strlcpy (data.server_name, p->server_name, sizeof(data.server_name));
	strlcpy (data.client_name, p->client_name, sizeof(data.client_name));

	if (data.server_name[0] == '\0')
	{
		if (!res->server.raw_smb && strlen (p->server_ipname) > 16)
		{
			ReportError("Server name '%s' is too long for NetBIOS (max %ld characters).",p->server_ipname,16);

			(*error_ptr) = ENAMETOOLONG;
			goto error_occured;
		}

		strlcpy (data.server_name, p->server_ipname, sizeof(data.server_name));
	}

	StringToUpper (data.server_name);

	if (data.client_name[0] == '\0')
	{
		if (!res->server.raw_smb && strlen (hostname) > 16)
		{
			ReportError("Local host name '%s' is too long for NetBIOS (max %ld characters).", hostname, 16);

			(*error_ptr) = ENAMETOOLONG;
			goto error_occured;
		}

		strlcpy (data.client_name, hostname, sizeof(data.client_name));
		StringToUpper (data.client_name);
	}

	res->server.mount_data = data;

	NewList((struct List *)&res->open_files);

	if (smb_proc_connect (&res->server, error_ptr) < 0)
		goto error_occured;

	if (!use_E)
		res->supports_E_known = TRUE;

	(*smba_server_ptr) = res;
	res = NULL;

	result = 0;

 error_occured:

	if(res != NULL)
	{
		(*smb_error_class_ptr) = res->server.rcls;
		(*smb_error_ptr) = res->server.err;

		smba_cleanup_dircache (res);
		free (res);
	}

	return result;
}

/*****************************************************************************/

void
smba_disconnect (smba_server_t * server)
{
	if(server->server.mount_data.fd >= 0)
		CloseSocket (server->server.mount_data.fd);

	smba_cleanup_dircache(server);

	free (server);
}

/*****************************************************************************/

static int
make_open (smba_file_t * f, int need_fid, int writable, int truncate, int * error_ptr)
{
	smba_server_t *s;
	int result;

	if (!f->is_valid || (need_fid && !f->dirent.opened))
	{
		ULONG now = GetCurrentTime();

		s = f->server;

		if (!f->is_valid || f->attr_time == 0 || (now > f->attr_time && now - f->attr_time > ATTR_CACHE_TIME))
		{
			if (f->server->server.protocol >= PROTOCOL_LANMAN2)
				result = smb_query_path_information (&s->server, f->dirent.complete_path, f->dirent.len, 0, &f->dirent, error_ptr);
			else
				result = smb_proc_getattr_core (&s->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);

			if (result < 0)
				goto out;
		}

		if ((f->dirent.attr & aDIR) == 0) /* a regular file */
		{
			if (f->server->server.protocol >= PROTOCOL_LANMAN2)
			{
				if(need_fid)
				{
					if(!f->dirent.opened)
					{
						LOG (("opening file %s\n", f->dirent.complete_path));

						result = smb_proc_open (&s->server, f->dirent.complete_path, f->dirent.len, writable, truncate, &f->dirent, error_ptr);
						if (result < 0)
							goto out;
					}
					else
					{
						LOG (("file %s is already open\n", f->dirent.complete_path));
					}
				}
			}
			else if (need_fid || !s->supports_E_known || s->supports_E)
			{
				if(!f->dirent.opened)
				{
					LOG (("opening file %s\n", f->dirent.complete_path));

					result = smb_proc_open (&s->server, f->dirent.complete_path, f->dirent.len, writable, truncate, &f->dirent, error_ptr);
					if (result < 0)
						goto out;
				}
				else
				{
					LOG (("file %s is already open\n", f->dirent.complete_path));
				}

				if (s->supports_E || !s->supports_E_known)
				{
					if (smb_proc_getattrE (&s->server, &f->dirent, error_ptr) < 0)
					{
						if (!s->supports_E_known)
						{
							s->supports_E_known	= TRUE;
							s->supports_E		= FALSE;
						} /* ignore errors here */
					}
					else
					{
						s->supports_E_known	= TRUE;
						s->supports_E		= TRUE;
					}
				}
			}
		}
		else
		{
			/* don't open directory, initialize directory cache */
			if (f->dircache != NULL)
			{
				f->dircache->cache_for	= NULL;
				f->dircache->len		= 0;
				f->dircache				= NULL;
			}
		}

		f->attr_time	= GetCurrentTime();
		f->is_valid		= TRUE;
	}

	result = 0;

 out:

	return result;
}

/*****************************************************************************/

int
smba_open (smba_server_t * s, char *name, size_t name_size, int writable, int truncate, smba_file_t ** file, int * error_ptr)
{
	smba_file_t *f;
	int result;

	(*file) = NULL;

	f = malloc (sizeof(*f));
	if(f == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memset(f,0,sizeof(*f));

	f->dirent.complete_path = name;
	f->dirent.complete_path_size = name_size;
	f->dirent.len = strlen (name);
	f->server = s;

	result = make_open (f, open_dont_need_fid, writable, truncate, error_ptr);
	if (result < 0)
		goto out;

	AddTail ((struct List *)&s->open_files, (struct Node *)f);

	(*file) = f;
	f = NULL;

 out:

	if (f != NULL)
		free (f);

	return result;
}

/*****************************************************************************/

static int
write_attr (smba_file_t * f, int * error_ptr)
{
	int result;

	LOG (("file %s\n", f->dirent.complete_path));

	if(f->server->server.protocol >= PROTOCOL_LANMAN2)
	{
		result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
		if (result < 0)
			goto out;

		result = smb_set_file_information (&f->server->server, &f->dirent, NULL, error_ptr);
	}
	else
	{
		result = make_open (f, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
		if (result < 0)
			goto out;

		if (f->dirent.opened && f->server->supports_E)
			result = smb_proc_setattrE (&f->server->server, f->dirent.fileid, &f->dirent, error_ptr);
		else
			result = smb_proc_setattr_core (&f->server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
	}

	if (result < 0)
	{
		f->attr_time = 0;
		goto out;
	}

	f->attr_dirty = FALSE;

 out:

	return result;
}

/*****************************************************************************/

void
smba_close (smba_file_t * f, int * error_ptr)
{
	if(f != NULL)
	{
		if(f->node.mln_Succ != NULL || f->node.mln_Pred != NULL)
			Remove((struct Node *)f);

		if(f->attr_dirty)
			write_attr(f, error_ptr);

		if (f->dirent.opened)
		{
			LOG (("closing file %s\n", f->dirent.complete_path));
			smb_proc_close (&f->server->server, f->dirent.fileid, f->dirent.mtime, error_ptr);
		}

		if (f->dircache != NULL)
		{
			f->dircache->cache_for = NULL;
			f->dircache->len = 0;
			f->dircache = NULL;
		}

		free (f);
	}
}

/*****************************************************************************/

int
smba_read (smba_file_t * f, char *data, long len, long offset, int * error_ptr)
{
	int max_receive = f->server->server.max_recv;
	int num_bytes_read = 0;
	int result;

	result = make_open (f, open_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	D(("read %ld bytes from offset %ld",len,offset));

	if (f->server->server.protocol >= PROTOCOL_LANMAN1)
	{
		int max_readx_size;
		int count;

		/* Calculate maximum number of bytes that could be transferred with
		 * a single SMBreadX packet...
		 *
		 * The message header accounts for
		 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
		 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
		 * = 32 bytes
		 *
		 * The parameters of a SMB_COM_READ_ANDX response account for
		 * 1(wordcount)+1(andxcommand)+1(andxreserved)+2(andxoffset)+
		 * 2(available)+2(datacompactionmode)+2(reserved)+2(datalength)+
		 * 2(dataoffset)+10(reserved2)
		 * = 25 bytes
		 *
		 * The data part of a SMB_COM_READ_ANDX response account for
		 * 2(bytecount)+1(pad) = 3 bytes,
		 * not including the actual payload
		 *
		 * This leaves 'max_receive' - 60 for the payload.
		 */

		max_readx_size = f->server->server.max_buffer_size - 60;

		if((f->server->server.capabilities & CAP_LARGE_READX) != 0)
			max_readx_size = 65535;

		/* ZZZ SMB_COM_READ_ANDX uses the packet buffer to receive
		 * the data, which is why there is another limit to how
		 * much data can be received.
		 */
		if(max_readx_size > f->server->server.transmit_buffer_size - 62)
			max_readx_size = f->server->server.transmit_buffer_size - 62;

		LOG (("len = %ld, max_readx_size = %ld\n", len, max_readx_size));

		do
		{
			count = min(len, max_readx_size);

			result = smb_proc_readx (&f->server->server, &f->dirent, offset, count, data, error_ptr);
			if (result < 0)
				goto out;

			num_bytes_read += result;
			len -= result;
			offset += result;
			data += result;

			if(result < count)
			{
				D(("read returned fewer characters than expected (%ld < %ld)",result,count));
				break;
			}
		}
		while (len > 0);
	}
	/* SMB_COM_READ_RAW and SMB_COM_WRITE_RAW supported? */
	else if ((f->server->server.capabilities & CAP_RAW_MODE) != 0 && !f->server->server.disable_read_raw)
	{
		int max_raw_size = f->server->server.max_raw_size;
		int n;

		do
		{
			/* SMB_COM_READ_RAW can only read up to 65535 bytes. */
			n = min(len, 65535);

			/* The maximum number of bytes to be read in raw
			 * mode may be limited, too.
			 */
			if(n > max_raw_size)
				n = max_raw_size;

			/* Limit how much data we are prepared to receive? */
			if(n > max_receive)
				n = max_receive;

			result = smb_proc_read_raw (&f->server->server, &f->dirent, offset, n, data, error_ptr);
			if(result <= 0)
			{
				D(("!!! wanted to read %ld bytes, got %ld",n,result));
				break;
			}

			num_bytes_read += result;
			len -= result;
			offset += result;
			data += result;

			if(result < n)
			{
				D(("read returned fewer characters than expected (%ld < %ld)",result,n));
				break;
			}
		}
		while(len > 0);
	}
	else
	{
		int max_size_smb_com_read;
		int count;

		/* Calculate maximum number of bytes that could be transferred with
		 * a single SMBread packet...
		 *
		 * 'max_buffer_size' is the maximum size of a complete SMB message
		 * including the message header, the parameter and data blocks.
		 *
		 * The message header accounts for
		 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
		 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
		 * = 32 bytes
		 *
		 * The parameters of a SMB_COM_READ response account for
		 * 1(wordcount)+2(countofbytesreturned)+8(reserved)
		 * = 11 bytes
		 *
		 * The data part of a SMB_COM_READ response account for
		 * 2(bytecount)+1(bufferformat)+2(countofbytesread) = 5 bytes,
		 * not including the actual payload
		 *
		 * This leaves 'max_buffer_size' - 48 for the payload.
		 */
		/*max_size_smb_com_read = f->server->server.max_buffer_size - SMB_HEADER_LEN - 5 * 2 - 5;*/
		max_size_smb_com_read = f->server->server.max_buffer_size - 48;

		/* ZZZ SMB_COM_READ uses the packet buffer to receive
		 * the data, which is why there is another limit to how
		 * much data can be received.
		 */
		if(max_size_smb_com_read > f->server->server.transmit_buffer_size - 48)
			max_size_smb_com_read = f->server->server.transmit_buffer_size - 48;

		do
		{
			/* SMB_COM_READ can read only up to 65535 bytes anyway. */
			count = min(len, 65535);
			if(count == 0)
				break;

			if(count > max_size_smb_com_read)
				count = max_size_smb_com_read;

			/* Limit how much data we are prepared to receive? */
			if(count > max_receive)
				count = max_receive;

			result = smb_proc_read (&f->server->server, &f->dirent, offset, count, data, error_ptr);
			if (result < 0)
				goto out;

			num_bytes_read += result;
			len -= result;
			offset += result;
			data += result;

			if(result < count)
			{
				D(("read returned fewer characters than expected (%ld < %ld)",result,count));
				break;
			}
		}
		while (len > 0);
	}

	result = num_bytes_read;

 out:

	return result;
}

/*****************************************************************************/

int
smba_write (smba_file_t * f, const char *data, long len, long offset, int * error_ptr)
{
	int num_bytes_written = 0;
	int max_buffer_size;
	int result;

	result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	SHOWVALUE(f->server->server.max_buffer_size);

	max_buffer_size = f->server->server.max_buffer_size;

	/* SMB_COM_WRITE_ANDX supported? */
	if (f->server->server.protocol >= PROTOCOL_LANMAN1)
	{
		int max_writex_size;
		int n;

		/* Calculate maximum number of bytes that could be transferred with
		 * a single SMB_COM_WRITE_ANDX packet...
		 *
		 * 'max_buffer_size' is the maximum size of a complete SMB message
		 * including the message header, the parameter and data blocks.
		 *
		 * The message header accounts for
		 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
		 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
		 * = 32 bytes
		 *
		 * The parameters of a SMB_COM_WRITE_ANDX command account for
		 * 1(word_count)+1(and_x_command)+1(and_x_reserved)+2(and_x_offset)+
		 * 2(fid)+4(offset)+4(timeout)+2(write_mode)+2(remaining)+2(reserved)+
		 * 2(data_length)+2(data_offset)+4(offset_high)
		 * = 29 bytes
		 *
		 * The data part of a SMB_COM_WRITE_ANDX command account for
		 * 2(byte_count)+1(pad) = 3 bytes, not including
		 * the actual payload
		 *
		 * This leaves 'max_buffer_size' - 64 for the payload.
		 */

		if(f->server->server.protocol >= PROTOCOL_NT1)
			max_writex_size = max_buffer_size - 64;
		else
			max_writex_size = max_buffer_size - 60;

		if((f->server->server.capabilities & CAP_LARGE_WRITEX) != 0)
			max_writex_size = 65535;

		LOG (("len = %ld, max_writex_size = %ld\n", len, max_writex_size));

		do
		{
			n = min(len, max_writex_size);

			ASSERT( n > 0 );

			LOG(("writing %ld bytes; offset=%lu, len=%ld\n", n, offset, len));

			result = smb_proc_writex(&f->server->server, &f->dirent, offset, n, data, error_ptr);
			if(result < 0)
				goto out;

			LOG(("number of bytes written = %ld\n", result));

			data += result;
			offset += result;
			len -= result;
			num_bytes_written += result;
		}
		while(len > 0);
	}
	else if ((f->server->server.capabilities & CAP_RAW_MODE) != 0 && !f->server->server.disable_write_raw)
	{
		int max_raw_size = f->server->server.max_raw_size;
		int max_size_smb_com_write_raw;
		int n;

		/* Try to send the maximum number of bytes with the two SMBwritebraw packets.
		 * This is how it breaks down:
		 *
		 * The message header accounts for
		 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
		 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
		 * = 32 bytes
		 *
		 * The parameters of a SMB_COM_WRITE_RAW command account for
		 * 1(wordcount)+2(fid)+2(countofbytes)+2(reserved1)+4(offset)+
		 * 4(timeout)+2(writemode)+4(reserved2)+2(datalength)+
		 * 2(dataoffset) = 25 bytes
		 *
		 * The data part of a SMB_COM_WRITE_RAW command accounts for
		 * 2(bytecount) = 2 bytes
		 *
		 * This leaves 'max_buffer_size' - 59 for the payload.
		 */
		/*max_size_smb_com_write_raw = 2 * f->server->server.max_buffer_size - (SMB_HEADER_LEN + 12 * sizeof (word) + 4) - 8;*/
		max_size_smb_com_write_raw = max(max_buffer_size, max_raw_size) - 59;

		/* SMB_COM_WRITE_RAW cannot transmit more than 65535 bytes. */
		if(max_size_smb_com_write_raw > 65535)
			max_size_smb_com_write_raw = 65535;

		LOG (("len = %ld, max_size_smb_com_write_raw = %ld\n", len, max_size_smb_com_write_raw));

		do
		{
			n = min(len, max_size_smb_com_write_raw);

			ASSERT( n > 0 );

			if(n > max_raw_size)
				n = max_raw_size;

			ASSERT( n <= 65535 );

			result = smb_proc_write_raw (&f->server->server, &f->dirent, offset, n, data, error_ptr);
			if(result < 0)
				goto out;

			data += result;
			offset += result;
			len -= result;
			num_bytes_written += result;
		}
		while(len > 0);
	}
	else
	{
		int max_size_smb_com_write, count;

		/* Calculate maximum number of bytes that could be transferred with
		 * a single SMBwrite packet...
		 *
		 * 'max_buffer_size' is the maximum size of a complete SMB message
		 * including the message header, the parameter and data blocks.
		 *
		 * The message header accounts for
		 * 4(protocol)+1(command)+4(status)+1(flags)+2(flags2)+2(pidhigh)+
		 * 8(securityfeatures)+2(reserved)+2(tid)+2(pidlow)+2(uid)+2(mid)
		 * = 32 bytes
		 *
		 * The parameters of a SMB_COM_WRITE command account for
		 * 1(wordcount)+2(fid)+2(countofbytestowrite)+4(writeoffsetinbytes)+
		 * 2(estimateofremainingbytestobewritten) = 11 bytes
		 *
		 * The data part of a SMB_COM_WRITE command account for
		 * 2(bytecount)+1(bufferformat)+2(datalength) = 5 bytes, not including
		 * the actual payload
		 *
		 * This leaves 'max_buffer_size' - 48 for the payload.
		 */
		/*max_size_smb_com_write = f->server->server.max_buffer_size - (SMB_HEADER_LEN + 5 * sizeof (word) + 5) - 4;*/
		max_size_smb_com_write = max_buffer_size - 48;

		/* SMB_COM_WRITE cannot transmit more than 65535 bytes. */
		if(max_size_smb_com_write > 65535)
			max_size_smb_com_write = 65535;

		LOG (("len = %ld, max_size_smb_com_write = %ld\n", len, max_size_smb_com_write));

		do
		{
			count = min(len, max_size_smb_com_write);
			if(count == 0)
				break;

			ASSERT( count <= 65535 );

			result = smb_proc_write (&f->server->server, &f->dirent, offset, count, data, error_ptr);
			if (result < 0)
				goto out;

			len -= result;
			offset += result;
			data += result;
			num_bytes_written += result;
		}
		while (len > 0);
	}

	LOG(("num_bytes_written=%ld\n", num_bytes_written));

	result = num_bytes_written;

 out:

	if (result < 0)
		f->attr_time = 0;
	else if (result > 0)
		f->dirent.mtime = GetCurrentTime();

	/* Even if one write access failed, we may have succeeded
	 * at writing some data. Hence we update the cached file
	 * size here.
	 */
	if (offset + num_bytes_written > (int)f->dirent.size)	/* ZZZ overflow check needed? */
		f->dirent.size = offset + num_bytes_written;

	return result;
}

/*****************************************************************************/

/* perform a single record-lock */
int
smba_lockrec (smba_file_t *f, long offset, long len, long mode, int unlocked, long timeout, int * error_ptr)
{
	struct smb_lkrng *rec_lock = NULL;
	int result;

	result = make_open (f, open_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if(result < 0)
		goto out;

	if (unlocked)
		mode |= 2;

	rec_lock = malloc (sizeof (*rec_lock));
	if (rec_lock == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	rec_lock->offset = offset,
	rec_lock->len = len;

	result = smb_proc_lockingX (&f->server->server, &f->dirent, rec_lock, 1, mode, timeout, error_ptr);

 out:

	if(rec_lock != NULL)
		free (rec_lock);

	return(result);
}

/*****************************************************************************/

int
smba_getattr (smba_file_t * f, smba_stat_t * data, int * error_ptr)
{
	int result;
	ULONG now;

	result = make_open (f, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	now = GetCurrentTime();

	if (f->attr_time == 0 || (now > f->attr_time && now - f->attr_time > ATTR_CACHE_TIME))
	{
		LOG (("file %s\n", f->dirent.complete_path));

		if (f->server->server.protocol >= PROTOCOL_LANMAN2)
		{
			if (f->dirent.opened)
				result = smb_query_path_information (&f->server->server, NULL, 0, f->dirent.fileid, &f->dirent, error_ptr);
			else
				result = smb_query_path_information (&f->server->server, f->dirent.complete_path, f->dirent.len, 0, &f->dirent, error_ptr);
		}
		else
		{
			if (f->dirent.opened && f->server->supports_E)
				result = smb_proc_getattrE (&f->server->server, &f->dirent, error_ptr);
			else
				result = smb_proc_getattr_core (&f->server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
		}

		if (result < 0)
			goto out;

		f->attr_time = now;
	}

	data->is_dir = (f->dirent.attr & aDIR) != 0;
	data->is_read_only = (f->dirent.attr & aRONLY) != 0;
	data->is_hidden = (f->dirent.attr & aHIDDEN) != 0;
	data->is_system = (f->dirent.attr & aSYSTEM) != 0;
	data->is_changed_since_last_archive = (f->dirent.attr & aARCH) != 0;

	data->size = f->dirent.size;
	data->atime = f->dirent.atime;
	data->ctime = f->dirent.ctime;
	data->mtime = f->dirent.mtime;

 out:

	return(result);
}

/*****************************************************************************/

int
smba_setattr (smba_file_t * f, const smba_stat_t * data, const dword * size_ptr, int * error_ptr)
{
	BOOL times_changed = FALSE;
	int result = 0;
	dword attrs;

	if (data != NULL)
	{
		if (data->atime != -1 && f->dirent.atime != data->atime)
		{
			f->dirent.atime = data->atime;
			times_changed = TRUE;
		}

		if (data->ctime != -1 && f->dirent.ctime != data->ctime)
		{
			f->dirent.ctime = data->ctime;
			times_changed = TRUE;
		}

		if (data->mtime != -1 && f->dirent.mtime != data->mtime)
		{
			f->dirent.mtime = data->mtime;
			times_changed = TRUE;
		}

		attrs = f->dirent.attr;

		if (data->is_read_only)
			attrs |= aRONLY;
		else
			attrs &= ~aRONLY;

		if (data->is_changed_since_last_archive)
			attrs |= aARCH;
		else
			attrs &= ~aARCH;

		/*
		if (data->is_system)
			attrs |= aSYSTEM;
		else
			attrs &= ~aSYSTEM;
		*/

		if(f->dirent.attr != attrs)
		{
			f->dirent.attr = attrs;
			f->attr_dirty = TRUE;
		}

		if(f->attr_dirty || times_changed)
		{
			result = write_attr (f, error_ptr);
			if (result < 0)
				goto out;
		}
	}

	if (size_ptr != NULL && (*size_ptr) != f->dirent.size)
	{
		result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
		if(result < 0)
			goto out;

		if(f->server->server.protocol >= PROTOCOL_LANMAN2)
			result = smb_set_file_information (&f->server->server, &f->dirent, size_ptr, error_ptr);
		else
			result = smb_proc_trunc (&f->server->server, f->dirent.fileid, (*size_ptr), error_ptr);

		if(result < 0)
			goto out;

		f->dirent.size = (*size_ptr);
	}

 out:

	return(result);
}

/*****************************************************************************/

int
smba_readdir (smba_file_t * f, long offs, void *d, smba_callback_t callback, int * error_ptr)
{
	int cache_index, o, eof, count = 0;
	int num_entries;
	smba_stat_t data;
	int result;
	ULONG now;

	result = make_open (f, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	now = GetCurrentTime();

	if (f->dircache == NULL) /* get a cache */
	{
		dircache_t * dircache = f->server->dircache;

		if (dircache->cache_for != NULL)
			dircache->cache_for->dircache = NULL; /* steal it */

		dircache->eof = dircache->len = dircache->base = 0;
		dircache->cache_for = f;

		f->dircache = dircache;

		LOG (("stealing cache\n"));
	}
	else
	{
		if (now > f->dircache->created_at && now - f->dircache->created_at >= DIR_CACHE_TIME)
		{
			f->dircache->eof = f->dircache->len = f->dircache->base = 0;

			LOG (("cache outdated\n"));
		}
	}

	for (cache_index = offs ; ; cache_index++)
	{
		if (cache_index < f->dircache->base /* fill cache if necessary */
		 || cache_index >= f->dircache->base + f->dircache->len)
		{
			if (cache_index >= f->dircache->base + f->dircache->len && f->dircache->eof)
				break; /* nothing more to read */

			LOG (("cachefill for %s\n", f->dirent.complete_path));
			LOG (("\tbase was: %ld, len was: %ld, newbase=%ld\n", f->dircache->base, f->dircache->len, cache_index));

			f->dircache->len = 0;
			f->dircache->base = cache_index;

			num_entries = smb_proc_readdir (&f->server->server, f->dirent.complete_path, cache_index, f->dircache->cache_size, f->dircache->cache, error_ptr);

			/* We stop on error, or if the directory is empty. */
			if (num_entries <= 0)
			{
				result = num_entries;
				goto out;
			}

			/* Avoid some hits if restart/retry occured. Should fix the real root
			 * of this problem really, but I am not bored enough atm. -Piru
			 */
			if (f->dircache == NULL)
			{
				LOG (("lost dircache due to an error, bailing out!\n"));

				(*error_ptr) = ENOMEM;

				result = -1;
				goto out;
			}

			f->dircache->len = num_entries;
			f->dircache->eof = (num_entries < f->dircache->cache_size);
			f->dircache->created_at = now;

			LOG (("cachefill with %ld entries\n", num_entries));
		}

		o = cache_index - f->dircache->base;
		eof = (o >= (f->dircache->len - 1) && f->dircache->eof);
		count++;

		LOG (("delivering '%s', cache_index=%ld, eof=%ld\n", f->dircache->cache[o].complete_path, cache_index, eof));

		data.is_dir							= (f->dircache->cache[o].attr & aDIR) != 0;
		data.is_read_only					= (f->dircache->cache[o].attr & aRONLY) != 0;
		data.is_hidden						= (f->dircache->cache[o].attr & aHIDDEN) != 0;
		data.is_system						= (f->dircache->cache[o].attr & aSYSTEM) != 0;
		data.is_changed_since_last_archive	= (f->dircache->cache[o].attr & aARCH) != 0;
		data.size							= f->dircache->cache[o].size;
		data.atime							= f->dircache->cache[o].atime;
		data.ctime							= f->dircache->cache[o].ctime;
		data.mtime							= f->dircache->cache[o].mtime;

		if ((*callback) (d, cache_index, cache_index + 1, f->dircache->cache[o].complete_path, eof, &data))
			break;
	}

	result = count;

 out:

	return result;
}

/*****************************************************************************/

static void
invalidate_dircache (struct smba_server * server, char * path)
{
	dircache_t * dircache = server->dircache;
	char other_path[SMB_MAXNAMELEN + 1];

	ENTER();

	if(path != NULL)
	{
		int len,i;

		strlcpy(other_path,path,sizeof(other_path));

		len = strlen(other_path);
		for(i = len-1 ; i >= 0 ; i--)
		{
			if(i == 0)
			{
				other_path[0] = DOS_PATHSEP;
				other_path[1] = '\0';
			}
			else if (other_path[i] == DOS_PATHSEP)
			{
				other_path[i] = '\0';
				break;
			}
		}
	}
	else
	{
		other_path[0] = '\0';
	}

	SHOWSTRING(other_path);

	if(dircache->cache_for != NULL)
		SHOWSTRING(dircache->cache_for->dirent.complete_path);
	else
		SHOWMSG("-- directory cache is empty --");

	if(path == NULL || (dircache->cache_for != NULL && CompareNames(other_path,dircache->cache_for->dirent.complete_path) == SAME))
	{
		SHOWMSG("clearing directory cache");

		dircache->eof = dircache->len = dircache->base = 0;
		if(dircache->cache_for != NULL)
		{
			dircache->cache_for->dircache = NULL;
			dircache->cache_for = NULL;
		}
	}

	LEAVE();
}

/*****************************************************************************/

int
smba_create (smba_file_t * dir, const char *name, smba_stat_t * attr, int * error_ptr)
{
	struct smb_dirent entry;
	char *path = NULL;
	size_t len;
	int result;

	result = make_open (dir, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	memset (&entry, 0, sizeof (entry));

	entry.atime = entry.mtime = entry.ctime = GetCurrentTime();

	len = strlen(name);

	path = malloc (len + 1 + dir->dirent.len + 1);
	if(path == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memcpy (path, dir->dirent.complete_path, dir->dirent.len);
	path[dir->dirent.len] = DOS_PATHSEP;
	memcpy(&path[dir->dirent.len+1], name, len+1);

	if (dir->server->server.protocol >= PROTOCOL_LANMAN2)
	{
		int ignored_error;

		result = smb_proc_open (&dir->server->server, path, strlen(path), open_writable, open_truncate, &entry, error_ptr);
		if(result < 0)
			goto out;

		/* Close the file again, we don't really need it right now. */
		smb_proc_close(&dir->server->server,entry.fileid,entry.mtime,&ignored_error);
	}
	else
	{
		result = smb_proc_create (&dir->server->server, path, strlen (path), &entry, error_ptr);
		if(result < 0)
			goto out;
	}

	invalidate_dircache (dir->server, path);

 out:

	if(path != NULL)
		free (path);

	return(result);
}

/*****************************************************************************/

int
smba_mkdir (smba_file_t * dir, const char *name, int * error_ptr)
{
	char *path = NULL;
	int result;

	result = make_open (dir, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	path = malloc (strlen (name) + dir->dirent.len + 2);
	if(path == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	memcpy (path, dir->dirent.complete_path, dir->dirent.len);
	path[dir->dirent.len] = DOS_PATHSEP;
	strcpy (&path[dir->dirent.len + 1], name);

	result = smb_proc_mkdir (&dir->server->server, path, strlen (path), error_ptr);
	if(result < 0)
		goto out;

	invalidate_dircache (dir->server, path);

 out:

	if(path != NULL)
		free (path);

	return(result);
}

/*****************************************************************************/

static int
close_path (smba_server_t * s, char *path, int * error_ptr)
{
	int result = 0;
	smba_file_t *p;

	for (p = (smba_file_t *)s->open_files.mlh_Head;
	     p->node.mln_Succ != NULL;
	     p = (smba_file_t *)p->node.mln_Succ)
	{
		if (p->is_valid && CompareNames(p->dirent.complete_path, path) == SAME)
		{
			if (p->dirent.opened)
			{
				result = smb_proc_close (&s->server, p->dirent.fileid, p->dirent.mtime, error_ptr);
				if(result < 0)
				{
					LOG(("closing %s with file id %ld failed\n", path, p->dirent.fileid));
					break;
				}

				p->dirent.opened = FALSE;
			}

			p->is_valid = FALSE;
		}
	}

	return(result);
}

/*****************************************************************************/

int
smba_remove (smba_server_t * s, char *path, int * error_ptr)
{
	int result;

	result = close_path (s, path, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_unlink (&s->server, path, strlen (path), error_ptr);
	if(result < 0)
		goto out;

	invalidate_dircache (s, path);

 out:

	return result;
}

/*****************************************************************************/

int
smba_rmdir (smba_server_t * s, char *path, int * error_ptr)
{
	int result;

	result = close_path (s, path, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_rmdir (&s->server, path, strlen (path), error_ptr);
	if(result < 0)
		goto out;

	invalidate_dircache (s, path);

 out:

	return result;
}

/*****************************************************************************/

int
smba_rename (smba_server_t * s, char *from, char *to, int * error_ptr)
{
	int result;

	result = close_path (s, from, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_mv (&s->server, from, strlen (from), to, strlen (to), error_ptr);
	if(result < 0)
		goto out;

	invalidate_dircache (s, from);

 out:

	return(result);
}

/*****************************************************************************/

int
smba_statfs (smba_server_t * s, long *bsize, long *blocks, long *bfree, int * error_ptr)
{
	struct smb_dskattr dskattr;
	int result;

	result = smb_proc_dskattr (&s->server, &dskattr, error_ptr);
	if (result < 0)
		goto out;

	(*bsize) = dskattr.blocksize * dskattr.allocblocks;
	(*blocks) = dskattr.total;
	(*bfree) = dskattr.free;

 out:

	return(result);
}

/*****************************************************************************/

void
smb_invalidate_all_inodes (struct smb_server *server)
{
	smba_file_t *f;

	invalidate_dircache (server->abstraction, NULL);

	for (f = (smba_file_t *)server->abstraction->open_files.mlh_Head;
	     f->node.mln_Succ != NULL;
	     f = (smba_file_t *)f->node.mln_Succ)
	{
		f->dirent.opened = FALSE;
		f->is_valid = FALSE;
	}
}

/*****************************************************************************/

static void
free_dircache(dircache_t * the_dircache)
{
	int i;

	for (i = 0; i < the_dircache->cache_size; i++)
	{
		if(the_dircache->cache[i].complete_path != NULL)
			free(the_dircache->cache[i].complete_path);
	}

	free(the_dircache);
}

static void
smba_cleanup_dircache(struct smba_server * server)
{
	dircache_t * the_dircache;

	the_dircache = server->dircache;
	if(the_dircache != NULL)
	{
		free_dircache(the_dircache);
		server->dircache = NULL;
	}
}

static int
smba_setup_dircache (struct smba_server * server,int cache_size, int * error_ptr)
{
	dircache_t * the_dircache;
	int result = -1;
	int i;

	the_dircache = malloc(sizeof(*the_dircache) + (cache_size-1) * sizeof(the_dircache->cache));
	if(the_dircache == NULL)
	{
		(*error_ptr) = ENOMEM;
		goto out;
	}

	memset(the_dircache,0,sizeof(*the_dircache));
	the_dircache->cache_size = cache_size;

	for (i = 0; i < the_dircache->cache_size; i++)
	{
		the_dircache->cache[i].complete_path = malloc (SMB_MAXNAMELEN + 1);
		if(the_dircache->cache[i].complete_path == NULL)
		{
			(*error_ptr) = ENOMEM;
			goto out;
		}

		the_dircache->cache[i].complete_path_size = SMB_MAXNAMELEN + 1;
	}

	server->dircache = the_dircache;
	the_dircache = NULL;

	result = 0;

 out:

	if(the_dircache != NULL)
		free_dircache(the_dircache);

	return(result);
}

/*****************************************************************************/

static int
extract_service (char *service, char *server, size_t server_size, char *share, size_t share_size,int * error_ptr)
{
	char * share_start;
	char * root_start;
	char * complete_service;
	char * service_copy;
	int result = -1;

	service_copy = malloc(strlen(service)+1);
	if(service_copy == NULL)
	{
		ReportError("Not enough memory.");

		(*error_ptr) = ENOMEM;

		goto out;
	}

	strcpy (service_copy, service);
	complete_service = service_copy;

	if (strlen (complete_service) < 4 || complete_service[0] != '/')
	{
		ReportError("Invalid service name '%s'.",complete_service);

		(*error_ptr) = EINVAL;

		goto out;
	}

	while (complete_service[0] == '/')
		complete_service += 1;

	share_start = strchr (complete_service, '/');
	if (share_start == NULL)
	{
		ReportError("Invalid share name '%s'.",complete_service);

		(*error_ptr) = EINVAL;

		goto out;
	}

	(*share_start++) = '\0';
	root_start = strchr (share_start, '/');

	if (root_start != NULL)
		(*root_start) = '\0';

	if ((strlen (complete_service) > 63) || (strlen (share_start) > 63))
	{
		ReportError("Server or share name is too long in '%s' (max %ld characters).",service,63);

		(*error_ptr) = ENAMETOOLONG;

		goto out;
	}

	strlcpy (server, complete_service, server_size);
	strlcpy (share, share_start, share_size);

	result = 0;

 out:

	if(service_copy != NULL)
		free(service_copy);

	return(result);
}

int
smba_start(
	char *				service,
	char *				opt_workgroup,
	char *				opt_username,
	char *				opt_password,
	char *				opt_clientname,
	char *				opt_servername,
	int					opt_cachesize,
	int					opt_max_transmit,
	int					opt_timeout,
	int					opt_raw_smb,
	int					opt_write_behind,
	int					opt_prefer_write_raw,
	int					opt_disable_write_raw,
	int					opt_disable_read_raw,
	char *				opt_native_os,
	int *				error_ptr,
	int *				smb_error_class_ptr,
	int *				smb_error_ptr,
	smba_server_t **	smba_server_ptr)
{
	smba_connect_parameters_t par;
	smba_server_t *the_server = NULL;
	int i;
	struct hostent *h;
	int use_extended = 0;
	char server_name[17], client_name[17]; /* Maximum length appears to be 16 characters for NetBIOS */
	char username[64], password[64];
	char workgroup[64]; /* Maximum length appears to be 15 characters */
	char server[64], share[64];
	in_addr_t ipAddr;
	int result = -1;

	ASSERT( error_ptr != NULL );
	ASSERT( smb_error_class_ptr != NULL );
	ASSERT( smb_error_ptr != NULL );

	(*error_ptr) = (*smb_error_class_ptr) = (*smb_error_ptr) = 0;
	(*smba_server_ptr) = NULL;
	(*username) = (*password) = (*server_name) = (*client_name) = '\0';

	if(extract_service (service, server, sizeof(server), share, sizeof(share), error_ptr) < 0)
		goto out;

	ipAddr = inet_addr (server);
	if (ipAddr == INADDR_NONE) /* name was given, not numeric */
	{
		int lookup_error;

		h = gethostbyname (server);
		lookup_error = h_errno;

		if (h != NULL)
		{
			ipAddr = ((struct in_addr *)(h->h_addr))->s_addr;
		}
		else if (BroadcastNameQuery(server,"",(UBYTE *)&ipAddr) != 0)
		{
			ReportError("Unknown host '%s' (%ld, %s).",server,lookup_error,host_strerror(lookup_error));

			(*error_ptr) = ENOENT;
			goto out;
		}
	}
	else
	{
		char hostName[MAXHOSTNAMELEN+1];

		h = gethostbyaddr ((char *) &ipAddr, sizeof (ipAddr), AF_INET);
		if (h == NULL)
		{
			ReportError("Unknown host '%s' (%ld, %s).",server,h_errno,host_strerror(errno));

			(*error_ptr) = ENOENT;
			goto out;
		}

		/* Brian Willette: Now we will set the server name to the DNS
		   hostname, hopefully this will be the same as the NetBIOS name for
		   the server.
		   We do this because the user supplied no hostname, and we
		   need one for NetBIOS, this is the best guess choice we have
		   NOTE: If the names are different between DNS and NetBIOS on
		   the windows side, the user MUST use the -s option. */
		for (i = 0; h->h_name[i] != '.' && h->h_name[i] != '\0' && i < 255; i++)
			hostName[i] = h->h_name[i];

		hostName[i] = '\0';

		/* Make sure the hostname is 16 characters or less (for NetBIOS) */
		if (!opt_raw_smb && strlen (hostName) > 16)
		{
			ReportError("Server host name '%s' is too long (max %ld characters).", hostName, 16);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy (server_name, hostName, sizeof(server_name));
	}

	if(opt_password != NULL)
	{
		if(strlen(opt_password) >= sizeof(password))
		{
			ReportError("Password is too long (max %ld characters).", sizeof(password)-1);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy(password,opt_password,sizeof(password));
	}

	if(strlen(opt_username) >= sizeof(username))
	{
		ReportError("User name '%s' is too long (max %ld characters).", username,sizeof(username)-1);

		(*error_ptr) = ENAMETOOLONG;
		goto out;
	}

	strlcpy(username,opt_username,sizeof(username));
	StringToUpper(username);

	/*
	if (strlen(opt_workgroup) > 15)
	{
		ReportError("Workgroup/domain name '%s' is too long (max %ld characters).", opt_workgroup,15);

		(*error_ptr) = ENAMETOOLONG;
		goto out;
	}
	*/

	strlcpy (workgroup, opt_workgroup, sizeof(workgroup));
	StringToUpper (workgroup);

	if(opt_servername != NULL)
	{
		if (!opt_raw_smb && strlen (opt_servername) > 16)
		{
			ReportError("Server name '%s' is too long (max %ld characters).", opt_servername,16);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy (server_name, opt_servername, sizeof(server_name));
	}

	if(opt_clientname != NULL)
	{
		if (!opt_raw_smb && strlen (opt_clientname) > 16)
		{
			ReportError("Client name '%s' is too long (max %ld characters).", opt_clientname,16);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy (client_name, opt_clientname, sizeof(client_name));
	}

	if(opt_cachesize < 1)
		opt_cachesize = DIRCACHE_SIZE;
	else if (opt_cachesize < 10)
		opt_cachesize = 10;

	strlcpy(par.server_ipname,server,sizeof(par.server_ipname));
	par.server_name = server_name;
	par.client_name = client_name;

	strlcpy(par.service,share,sizeof(par.service));
	par.username = username;
	par.password = password;

	if(smba_connect (
		&par,
		ipAddr,
		use_extended,
		workgroup,
		opt_cachesize,
		opt_max_transmit,
		opt_timeout,
		opt_raw_smb,
		opt_write_behind,
		opt_prefer_write_raw,
		opt_disable_write_raw,
		opt_disable_read_raw,
		opt_native_os,
		error_ptr,
		smb_error_class_ptr,
		smb_error_ptr,
		&the_server) < 0)
	{
		if((*error_ptr) == error_check_smb_error)
		{
			char * smb_class_name;
			char * smb_code_text;

			smb_translate_error_class_and_code((*smb_error_class_ptr),(*smb_error_ptr),&smb_class_name,&smb_code_text);

			ReportError("Could not connect to server (%ld/%ld, %s/%s).",(*smb_error_class_ptr),(*smb_error_ptr),smb_class_name,smb_code_text);
		}
		else
		{
			ReportError("Could not connect to server (%ld, %s).",(*error_ptr),posix_strerror(*error_ptr));
		}

		goto out;
	}

	(*smba_server_ptr) = the_server;

	result = 0;

 out:

	return(result);
}

/*****************************************************************************/

int
smba_get_dircache_size(struct smba_server * server)
{
	int result;

	result = server->dircache->cache_size;

	return(result);
}

/*****************************************************************************/

int
smba_change_dircache_size(struct smba_server * server,int cache_size)
{
	dircache_t * new_cache;
	dircache_t * old_dircache = server->dircache;
	int result;
	int i;

	result = old_dircache->cache_size;

	/* We have to have a minimum cache size. */
	if(cache_size < 10)
		cache_size = 10;

	/* Don't do anything if the cache size has not changed. */
	if(cache_size == old_dircache->cache_size)
		goto out;

	/* Allocate a new cache and set it up with defaults. Note that
	 * the file name pointers in the cache are still not initialized.
	 */
	new_cache = malloc(sizeof(*new_cache) + (cache_size-1) * sizeof(new_cache->cache));
	if(new_cache == NULL)
		goto out;

	memset(new_cache,0,sizeof(*new_cache));
	new_cache->cache_size = cache_size;

	/* If the new cache is to be larger than the old one, allocate additional file name slots. */
	if(cache_size > old_dircache->cache_size)
	{
		/* Initialize the file name pointers so that free_dircache()
		 * can be called safely, if necessary.
		 */
		for(i = 0 ; i < cache_size ; i++)
			new_cache->cache[i].complete_path = NULL;

		/* Allocate memory for the file names. */
		for(i = old_dircache->cache_size ; i < cache_size ; i++)
		{
			new_cache->cache[i].complete_path = malloc (SMB_MAXNAMELEN + 1);
			if(new_cache->cache[i].complete_path == NULL)
			{
				free_dircache(new_cache);
				goto out;
			}

			new_cache->cache[i].complete_path_size = SMB_MAXNAMELEN + 1;
		}

		/* Reuse the file name buffers allocated for the old cache. */
		for(i = 0 ; i < old_dircache->cache_size ; i++)
		{
			new_cache->cache[i].complete_path = old_dircache->cache[i].complete_path;
			new_cache->cache[i].complete_path_size = old_dircache->cache[i].complete_path_size;

			old_dircache->cache[i].complete_path = NULL;
		}
	}
	else
	{
		/* Reuse the file name buffers allocated for the old cache. */
		for(i = 0 ; i < cache_size ; i++)
		{
			new_cache->cache[i].complete_path = old_dircache->cache[i].complete_path;
			new_cache->cache[i].complete_path_size = old_dircache->cache[i].complete_path_size;

			old_dircache->cache[i].complete_path = NULL;
		}
	}

	invalidate_dircache(server, NULL);

	free_dircache(old_dircache);

	server->dircache = new_cache;
	result = cache_size;

 out:

	return(result);
}
