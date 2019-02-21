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
#include "quad_math.h"

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

#include "smb_abstraction.h"

/*****************************************************************************/

static int
dircache_has_expired(ULONG now, const dircache_t * dircache)
{
	int result;

	ASSERT( dircache != NULL );

	result = (now > dircache->created_at && (now - dircache->created_at) >= DIR_CACHE_TIME);

	return(result);
}

/*****************************************************************************/

static void
reset_dircache (dircache_t * dircache)
{
	ASSERT( dircache != NULL );

	dircache->eof = FALSE;
	dircache->cache_used = dircache->base = 0;
	dircache->is_valid = TRUE;
	dircache->sid = -1;
}

/*****************************************************************************/

/* Return the number of directory cache entries still
 * available to be filled with data.
 */
int
get_dircache_entries_available(const dircache_t * dircache)
{
	ASSERT( dircache != NULL );
	ASSERT( dircache->cache_used <= dircache->cache_size );

	return(dircache->cache_size - dircache->cache_used);
}

/*****************************************************************************/

/* Get the first directory cache entry, or return NULL
 * if the cache has been invalidated.
 */
struct smb_dirent *
get_first_dircache_entry(dircache_t * dircache)
{
	struct smb_dirent * result;

	ASSERT( dircache != NULL );

	if(dircache->is_valid)
	{
		dircache->cache_used = 0;

		result = &dircache->cache[dircache->cache_used];
	}
	else
	{
		result = NULL;
	}

	return(result);
}

/*****************************************************************************/

/* Get the next available directory cache entry, or return
 * NULL if the cache has been exhauste (or is no longer valid).
 */
struct smb_dirent *
get_next_dircache_entry(dircache_t * dircache)
{
	struct smb_dirent * result = NULL;

	ASSERT( dircache != NULL );

	if(dircache->is_valid && dircache->cache_used < dircache->cache_size)
	{
		LOG(("read directory entry '%s', now %ld entries in cache (of %ld)\n",
			escape_name(dircache->cache[dircache->cache_used].complete_path),
			dircache->cache_used+1,
			dircache->cache_size));

		dircache->cache_used++;

		if(dircache->cache_used < dircache->cache_size)
			result = &dircache->cache[dircache->cache_used];
		else
			LOG(("directory cache is now full\n"));
	}

	return(result);
}

/*****************************************************************************/

/* Invalidate the directory cache, which has the effect that adding
 * new entries to it will fail until it has been reinitialized
 * by reset_dircache().
 */
static void
invalidate_dircache(dircache_t * dircache)
{
	ENTER();

	ASSERT( dircache != NULL );

	dircache->eof = TRUE;
	dircache->cache_used = dircache->base = 0;
	dircache->is_valid = FALSE;
	dircache->sid = -1;

	if(dircache->cache_for != NULL)
	{
		LOG(("invalidating directory cache for '%s'\n", escape_name(dircache->cache_for->dirent.complete_path)));

		dircache->cache_for->dircache = NULL;
		dircache->cache_for = NULL;
	}

	LEAVE();
}

/*****************************************************************************/

static void
free_dircache(dircache_t * dircache)
{
	int i;

	ASSERT( dircache != NULL );

	for (i = 0; i < dircache->cache_size; i++)
	{
		if(dircache->cache[i].complete_path != NULL)
			free(dircache->cache[i].complete_path);
	}

	free(dircache);
}

/*****************************************************************************/

static dircache_t *
allocate_dircache(int cache_size)
{
	const int complete_path_size = SMB_MAXNAMELEN + 1;
	dircache_t * result = NULL;
	dircache_t * dircache;
	int i;

	ENTER();

	dircache = malloc(sizeof(*dircache) + (cache_size-1) * sizeof(dircache->cache));
	if(dircache == NULL)
		goto out;

	memset(dircache, 0, sizeof(*dircache));
	dircache->cache_size = cache_size;

	/* Make sure that free_dircache() will not end up
	 * releasing invalid memory.
	 */
	for (i = 0; i < dircache->cache_size; i++)
		dircache->cache[i].complete_path = NULL;

	for (i = 0; i < dircache->cache_size; i++)
	{
		dircache->cache[i].complete_path = malloc (complete_path_size);
		if (dircache->cache[i].complete_path == NULL)
			goto out;

		dircache->cache[i].complete_path_size = complete_path_size;
	}

	invalidate_dircache(dircache);

	result = dircache;
	dircache = NULL;

 out:

	if(dircache != NULL)
		free_dircache(dircache);

	RETURN(result);
	return(result);
}

/*****************************************************************************/

static void
cleanup_server_dircache(struct smba_server * server)
{
	dircache_t * dircache;

	while((dircache = (dircache_t *)RemHead((struct List *)&server->dircache_list)) != NULL)
		free_dircache(dircache);
}

/*****************************************************************************/

static int
setup_server_dircache(struct smba_server * server, int cache_size, int dircache_list_size)
{
	dircache_t * dircache;
	int result = -1;
	int i;

	if(dircache_list_size < 1)
		dircache_list_size = 1;

	for(i = 0 ; i < dircache_list_size ; i++)
	{
		dircache = allocate_dircache(cache_size);
		if(dircache == NULL)
			goto out;

		AddTail((struct List *)&server->dircache_list, (struct Node *)dircache);
	}

	server->dircache_list_size = dircache_list_size;

	result = 0;

 out:

	if(result != 0)
		cleanup_server_dircache(server);

	return(result);
}

/*****************************************************************************/

#ifdef USE_SPLAY_TREE

/* This is used by the splay tree functions to compare individual
 * key values. These key values are smba_file_t addresses.
 */
static int
compare_files_by_address(const BYTE * a, const BYTE * b)
{
	int result;

	if (a < b)
		result = -1;
	else if (a == b)
		result = 0;
	else
		result = 1;

	return(result);
}

#endif /* USE_SPLAY_TREE */

/*****************************************************************************/

static void
init_open_file_list(smba_server_t *res)
{
	NewList((struct List *)&res->open_files);

	#ifdef USE_SPLAY_TREE
	{
		splay_tree_init(&res->open_file_address_tree, (splay_key_compare_t)compare_files_by_address);

		splay_tree_init(&res->open_file_name_tree, (splay_key_compare_t)compare_names);
		res->open_file_name_tree.st_allow_duplicates = TRUE;
	}
	#endif /* USE_SPLAY_TREE */
}

/*****************************************************************************/

static int
smba_connect (
	smba_connect_parameters_t *	connect_parameters,
	struct sockaddr_in			server_ip_addr,
	const char *				tcp_service_name,
	int							use_E,
	const char *				workgroup_name,
	int							cache_size,
	int							opt_cache_tables,
	int							max_transmit,
	int							timeout,
	int							opt_raw_smb,
	int							opt_unicode,
	int							opt_prefer_core_protocol,
	int							opt_case_sensitive,
	int							opt_session_setup_delay_unicode,
	int							opt_write_behind,
	int							opt_smb_request_write_threshold,
	int							opt_smb_request_read_threshold,
	int							opt_scatter_gather,
	int							opt_tcp_no_delay,
	int							opt_socket_receive_buffer_size,
	int							opt_socket_send_buffer_size,
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
		report_error("Not enough memory.");

		(*error_ptr) = ENOMEM;
		goto error_occured;
	}

	memset (res, 0, sizeof(*res));
	memset (&data, 0, sizeof (data));
	memset (hostname, 0, sizeof (hostname));

	NewList ((struct List *)&res->dircache_list);

	/* Use raw SMB over TCP rather than NetBIOS. */
	if(opt_raw_smb)
		res->server.raw_smb = TRUE;

	LOG(("use raw SMB = %s\n",opt_raw_smb ? "yes" : "no"));

	/* Timeout for send/receive operations in seconds. */
	res->server.timeout = timeout;

	LOG(("send/receive/connect timeout = %ld seconds%s\n",timeout,timeout > 0 ? "" : " (= default timeout)"));

	/* Enable Unicode support if the server supports it, too. */
	res->server.use_unicode = opt_unicode;

	LOG(("use Unicode = %s\n",opt_unicode ? "yes" : "no"));

	/* Prefer SMB core protocol commands to NT1 commands, if possible. */
	res->server.prefer_core_protocol = opt_prefer_core_protocol;

	LOG(("prefer core protocol = %s\n",opt_prefer_core_protocol ? "yes" : "no"));

	/* Path names are case-sensitive. */
	res->server.case_sensitive = opt_case_sensitive;

	LOG(("path names are case sensitive = %s\n",opt_case_sensitive ? "yes" : "no"));

	/* Delay the use of Unicode strings during session setup. */
	res->server.session_setup_delay_unicode = opt_session_setup_delay_unicode;

	LOG(("delay use of unicode during session setup = %s\n",opt_session_setup_delay_unicode ? "yes" : "no"));

	/* Do not send SMB header and payload for write operations separately,
	 * but in a single chunk if their combined size is smaller than
	 * or equal to this threshold value.
	 */
	res->server.smb_write_threshold = opt_smb_request_write_threshold;

	LOG(("SMB write request threshold size = %ld bytes\n", res->server.smb_write_threshold));

	/* Do not receive SMB header and payload for read operations separately,
	 * but in a single chunk if their combined size is smaller than
	 * or equal to this threshold value.
	 */
	res->server.smb_read_threshold = opt_smb_request_read_threshold;

	LOG(("SMB read request threshold size = %ld bytes\n", res->server.smb_read_threshold));

	/* Use sendmsg() instead of send() where useful? */
	res->server.scatter_gather = opt_scatter_gather;

	LOG(("use sendmsg() instead of send() where useful = %s\n",opt_scatter_gather ? "yes" : "no"));

	/* Disable the Nagle algorithm, causing send() to immediately
	 * result in the data being transmitted?
	 */
	res->server.tcp_no_delay = opt_tcp_no_delay;

	/* Try to get the TCP/IP stack to use a specific
	 * receive/transmit buffer size?
	 */
	res->server.socket_receive_buffer_size = opt_socket_receive_buffer_size;
	res->server.socket_send_buffer_size = opt_socket_send_buffer_size;

	/* Enable asynchronous SMB_COM_WRITE_RAW operations? */
	res->server.write_behind = opt_write_behind;

	LOG(("use asynchronous SMB_COM_WRITE_RAW operations = %s\n",opt_write_behind ? "yes" : "no"));

	LOG(("cache size = %ld entries\n", cache_size));

	if(setup_server_dircache (res, cache_size, opt_cache_tables) < 0)
	{
		(*error_ptr) = ENOMEM;

		report_error("Directory cache initialization failed (%ld, %s).",(*error_ptr),posix_strerror(*error_ptr));
		goto error_occured;
	}

	strlcpy(data.workgroup_name,workgroup_name,sizeof(data.workgroup_name));

	LOG(("workgroup name = '%s'\n",workgroup_name));

	res->server.abstraction = res;

	if(gethostname (hostname, MAXHOSTNAMELEN) < 0)
	{
		report_error("Could not look up local host name (%ld, %s).",(*error_ptr),posix_strerror(*error_ptr));
		goto error_occured;
	}

	/* Only retain the host name, drop any domain names following it. */
	if ((s = strchr (hostname, '.')) != NULL)
		(*s) = '\0';

	LOG(("local host name = '%s'\n",hostname));

	LOG(("server ip address = %s\n",Inet_NtoA(server_ip_addr.sin_addr.s_addr)));

	data.addr = server_ip_addr;

	/* Override the default TCP service name or port
	 * number which smbfs should connect to on the
	 * server?
	 */
	if(tcp_service_name[0] != '\0')
	{
		/* Try to find a service whose name matches. */
		servent = getservbyname((char *)tcp_service_name,"tcp");
		if(servent != NULL)
		{
			data.addr.sin_port = servent->s_port;

			LOG(("using port number %ld\n",ntohs(data.addr.sin_port)));
		}
		else
		{
			long int n;
			char * str;

			/* Try again, this time converting what's
			 * hopefully a number in the range
			 * valid for a TCP service.
			 */
			n = strtol(tcp_service_name,&str,10);
			if(str != tcp_service_name && (*str) == '\0')
			{
				if(0 < n && n < 65536)
				{
					data.addr.sin_port = htons (n);

					LOG(("using port number %ld\n",n));
				}
				else
				{
					report_error("Port number '%s' is out of range.", tcp_service_name);

					(*error_ptr) = EINVAL;
					goto error_occured;
				}
			}
			else
			{
				report_error("Invalid service '%s'.", tcp_service_name);

				(*error_ptr) = EINVAL;
				goto error_occured;
			}
		}
	}
	else if (res->server.raw_smb)
	{
		int port;

		servent = getservbyname("microsoft-ds","tcp");
		if(servent != NULL)
			port = servent->s_port;
		else
			port = htons (445);

		LOG(("using port number %ld\n",ntohs(port)));

		data.addr.sin_port = port;
	}
	else
	{
		int port;

		servent = getservbyname("netbios-ssn","tcp");
		if(servent != NULL)
			port = servent->s_port;
		else
			port = htons (139);

		LOG(("using port number %ld\n",ntohs(port)));

		data.addr.sin_port = port;
	}

	data.fd = socket (AF_INET, SOCK_STREAM, 0);
	if (data.fd < 0)
	{
		report_error("socket() call failed (%ld, %s).", errno, posix_strerror(errno));

		(*error_ptr) = errno;
		goto error_occured;
	}

	strlcpy (data.service, connect_parameters->service, sizeof(data.service));

	LOG(("service = '%s'\n",data.service));

	string_toupper (data.service);

	strlcpy (data.username, connect_parameters->username, sizeof(data.username));
	strlcpy (data.password, connect_parameters->password, sizeof(data.password));

	LOG(("user name = '%s'\n",data.username));

	data.given_max_xmit = max_transmit;

	LOG(("max transmit = %ld bytes\n",max_transmit));

	strlcpy (data.server_name, connect_parameters->server_name, sizeof(data.server_name));
	strlcpy (data.client_name, connect_parameters->client_name, sizeof(data.client_name));

	LOG(("server name = '%s'\n",data.server_name));
	LOG(("client name = '%s'\n",data.client_name));

	if (data.server_name[0] == '\0')
	{
		if (!res->server.raw_smb && strlen (connect_parameters->server_ipname) > 16)
		{
			report_error("Server name '%s' is too long for NetBIOS (%ld characters are possible).",connect_parameters->server_ipname,16);

			(*error_ptr) = ENAMETOOLONG;
			goto error_occured;
		}

		strlcpy (data.server_name, connect_parameters->server_ipname, sizeof(data.server_name));
	}

	string_toupper (data.server_name);

	if (data.client_name[0] == '\0')
	{
		if (!res->server.raw_smb && strlen (hostname) > 16)
		{
			report_error("Local host name '%s' is too long for NetBIOS (%ld characters are possible).", hostname, 16);

			(*error_ptr) = ENAMETOOLONG;
			goto error_occured;
		}

		strlcpy (data.client_name, hostname, sizeof(data.client_name));
		string_toupper (data.client_name);
	}

	res->server.mount_data = data;

	init_open_file_list(res);

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

		cleanup_server_dircache (res);
		free (res);
	}

	return result;
}

/*****************************************************************************/

void
smba_disconnect (smba_server_t * server)
{
	ASSERT( server != NULL );

	if(server->server.mount_data.fd >= 0)
		CloseSocket (server->server.mount_data.fd);

	cleanup_server_dircache(server);

	free (server);
}

/*****************************************************************************/

static int
file_attributes_are_stale(ULONG now, const smba_file_t * f)
{
	int result;

	ASSERT( f != NULL );

	result = (f->attr_time == 0 || (now > f->attr_time && (now - f->attr_time) > ATTR_CACHE_TIME));

	return(result);
}

/*****************************************************************************/

static int
make_open (smba_file_t * f, int need_fid, int writable, int truncate_file, int * error_ptr)
{
	smba_server_t *server;
	int result;

	ENTER();

	if (!f->is_valid || (need_fid && !f->dirent.opened))
	{
		ULONG now = get_current_time();

		server = f->server;

		if (!f->is_valid || file_attributes_are_stale(now, f))
		{
			if (!f->is_valid || f->attr_time == 0)
				LOG(("file attributes not yet known\n"));
			else
				LOG(("file attributes need to be updated\n"));

			if (!f->server->server.prefer_core_protocol && f->server->server.protocol >= PROTOCOL_LANMAN2)
			{
				LOG(("using the LAN Manager 2.0 getattr() variant\n"));

				result = smb_query_path_information (&server->server, f->dirent.complete_path, f->dirent.len, 0, &f->dirent, error_ptr);
			}
			else
			{
				LOG(("using the legacy getattr() variant\n"));

				result = smb_proc_getattr_core (&server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
			}

			if (result < 0)
				goto out;
		}

		if ((f->dirent.attr & SMB_FILE_ATTRIBUTE_DIRECTORY) == 0) /* a regular file */
		{
			if (f->server->server.protocol >= PROTOCOL_LANMAN2)
			{
				if(need_fid)
				{
					if(!f->dirent.opened)
					{
						LOG (("opening file '%s'\n", escape_name(f->dirent.complete_path)));

						LOG(("using the LAN Manager 2.0 open() variant\n"));

						result = smb_proc_open (&server->server, f->dirent.complete_path, f->dirent.len, writable, truncate_file, &f->dirent, error_ptr);
						if (result < 0)
							goto out;
					}
					else
					{
						LOG (("file '%s' is already open (fileid=0x%04lx)\n", escape_name(f->dirent.complete_path), f->dirent.fileid));
					}
				}
			}
			else if (need_fid || !server->supports_E_known || server->supports_E)
			{
				if(!f->dirent.opened)
				{
					LOG (("opening file '%s'\n", escape_name(f->dirent.complete_path)));

					LOG(("using the legacy open() variant\n"));

					result = smb_proc_open (&server->server, f->dirent.complete_path, f->dirent.len, writable, truncate_file, &f->dirent, error_ptr);
					if (result < 0)
						goto out;
				}
				else
				{
					LOG (("file '%s' is already open (fileid=0x%04lx)\n", escape_name(f->dirent.complete_path), f->dirent.fileid));
				}

				if (server->supports_E || !server->supports_E_known)
				{
					if (smb_proc_getattrE (&server->server, &f->dirent, error_ptr) < 0)
					{
						if (!server->supports_E_known)
						{
							server->supports_E_known	= TRUE;
							server->supports_E		= FALSE;
						} /* ignore errors here */
					}
					else
					{
						server->supports_E_known	= TRUE;
						server->supports_E		= TRUE;
					}
				}
			}
		}
		else
		{
			if (f->dircache != NULL)
			{
				LOG(("discarding the '%s' directory cache\n", escape_name(f->dirent.complete_path)));

				Remove((struct Node *)f->dircache);
				AddTail((struct List *)&server->dircache_list, (struct Node *)f->dircache);

				invalidate_dircache(f->dircache);
			}
		}

		f->attr_time	= get_current_time();
		f->is_valid		= TRUE;
	}

	result = 0;

 out:

	RETURN(result);
	return(result);
}

/*****************************************************************************/

static void
add_smba_file(smba_server_t * s, smba_file_t *f)
{
	AddTail ((struct List *)&s->open_files, (struct Node *)f);

	#ifdef USE_SPLAY_TREE
	{
		f->splay_address_node.sn_key = f;
		f->splay_address_node.sn_userdata = f;
		splay_tree_add(&s->open_file_address_tree, &f->splay_address_node);

		f->splay_name_node.sn_key = f->dirent.complete_path;
		f->splay_name_node.sn_userdata = f;
		splay_tree_add(&s->open_file_name_tree, &f->splay_name_node);
	}
	#endif /* USE_SPLAY_TREE */
}

/*****************************************************************************/

static void
remove_smba_file(smba_server_t * s, smba_file_t *f)
{
	Remove((struct Node *)f);

	#ifdef USE_SPLAY_TREE
	{
		splay_tree_remove(&s->open_file_address_tree, NULL, (splay_key_t)f);
		splay_tree_remove(&s->open_file_name_tree, &f->splay_name_node, f->splay_name_node.sn_key);
	}
	#endif /* USE_SPLAY_TREE */
}

/*****************************************************************************/

int
smba_open (
	smba_server_t * s,
	const char *name,
	int writable,
	int truncate_file,
	smba_file_t ** file,
	int * error_ptr)
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

	memset(f, 0, sizeof(*f));

	f->dirent.complete_path = (char *)name;
	f->dirent.len = strlen (name);
	f->server = s;

	LOG(("open '%s' (writable=%s, truncate_file=%s)\n",
		escape_name(name),
		writable ? "yes" : "no",
		truncate_file ? "yes" : "no"));

	result = make_open (f, open_dont_need_fid, writable, truncate_file, error_ptr);
	if (result < 0)
	{
		LOG(("open failed\n"));
		goto out;
	}

	add_smba_file(s, f);
	s->num_open_files++;

	LOG(("file has been 'opened', number of open files = %ld\n",s->num_open_files));

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

	LOG (("file '%s'\n", escape_name(f->dirent.complete_path)));

	LOG(("mtime = %lu\n",f->dirent.mtime));

	if(!f->server->server.prefer_core_protocol && f->server->server.protocol >= PROTOCOL_LANMAN2)
	{
		/* Copy these, because make_open() may overwrite them. */
		time_t mtime = f->dirent.mtime;
		time_t ctime = f->dirent.ctime;
		dword attr = f->dirent.attr;

		LOG(("mtime = %lu\n",f->dirent.mtime));
		LOG(("ctime = %lu\n",f->dirent.ctime));

		LOG(("using the LAN Manager 2.0 open() variant\n"));

		result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
		if (result < 0)
			goto out;

		LOG(("mtime = %lu\n",f->dirent.mtime));
		LOG(("ctime = %lu\n",f->dirent.ctime));

		f->dirent.mtime = mtime;
		f->dirent.ctime = ctime;
		f->dirent.attr = attr;

		result = smb_set_file_information (&f->server->server, &f->dirent, NULL, error_ptr);
		if (result < 0)
			goto out;

		f->attr_dirty = FALSE;
	}
	else
	{
		/* Copy these, because make_open() may overwrite them. */
		time_t mtime = f->dirent.mtime;
		time_t ctime = f->dirent.ctime;
		dword attr = f->dirent.attr;

		LOG(("mtime = %lu\n",f->dirent.mtime));
		LOG(("ctime = %lu\n",f->dirent.ctime));

		LOG(("using the legacy open() variant\n"));

		result = make_open (f, open_dont_need_fid, open_writable, open_dont_truncate, error_ptr);
		if (result < 0)
			goto out;

		LOG(("mtime = %lu\n",f->dirent.mtime));
		LOG(("ctime = %lu\n",f->dirent.ctime));

		f->dirent.mtime = mtime;
		f->dirent.ctime = ctime;
		f->dirent.attr = attr;

		/* If the attributes need to be updated, we cannot use smb_proc_setattrE(),
		 * because that only updates the "time of last write access", but not the
		 * attributes.
		 */
		if(f->attr_dirty)
		{
			/* Update the attributes and the "time of last write access". */
			result = smb_proc_setattr_core (&f->server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
			if(result < 0)
				goto out;

			/* Now deal with the creation/access/modification times. */
			if (f->dirent.opened && f->server->supports_E)
			{
				result = smb_proc_setattrE (&f->server->server, f->dirent.fileid, &f->dirent, error_ptr);
				if(result < 0)
					goto out;
			}

			f->attr_dirty = FALSE;
		}
		/* Update the times. */
		else
		{
			if (f->dirent.opened && f->server->supports_E)
				result = smb_proc_setattrE (&f->server->server, f->dirent.fileid, &f->dirent, error_ptr);
			else
				result = smb_proc_setattr_core (&f->server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
		}
	}

 out:

	if (result < 0)
		f->attr_time = 0;

	return result;
}

/*****************************************************************************/

static int
file_is_valid(smba_server_t * s, const smba_file_t * f)
{
	int is_valid;

	#ifndef USE_SPLAY_TREE
	{
		const smba_file_t * file;

		is_valid = FALSE;

		for (file = (smba_file_t *)s->open_files.mlh_Head ;
			file->node.mln_Succ != NULL ;
			file = (smba_file_t *)file->node.mln_Succ)
		{
			if (file == f)
			{
				is_valid = TRUE;
				break;
			}
		}
	}
	#else
	{
		is_valid = (splay_tree_find(&s->open_file_address_tree, (splay_key_t)f) != NULL);
	}
	#endif /* USE_SPLAY_TREE */

	return(is_valid);
}

/*****************************************************************************/

void
smba_close (smba_server_t * s, smba_file_t * f)
{
	ENTER();

	if (file_is_valid(s, f))
	{
		int ignored_error;

		remove_smba_file(s, f);

		if(f->attr_dirty)
			write_attr(f, &ignored_error);

		if (f->dirent.opened)
		{
			LOG (("closing file '%s' (fileid=0x%04lx)\n", escape_name(f->dirent.complete_path), f->dirent.fileid));

			/* Don't change the modification time. */
			smb_proc_close (&f->server->server, f->dirent.fileid, -1, &ignored_error);
		}

		/* release the directory cache */
		if (f->dircache != NULL)
		{
			Remove((struct Node *)f->dircache);
			AddTail((struct List *)&s->dircache_list, (struct Node *)f->dircache);

			invalidate_dircache(f->dircache);
		}

		f->server->num_open_files--;

		LOG(("file closed, number of open files = %ld\n",f->server->num_open_files));

		free (f);
	}
	else
	{
		LOG(("file seems to be invalid\n"));
	}

	LEAVE();
}

/*****************************************************************************/

int
smba_read (smba_file_t * f, char *data, long len, const QUAD * const offset, int * error_ptr)
{
	int max_receive = f->server->server.max_recv;
	int num_bytes_read = 0;
	int result;

	result = make_open (f, open_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	LOG(("read %ld bytes from offset %s\n",len,convert_quad_to_string(offset)));

	/* SMB_COM_READ_ANDX supported? */
	if (f->server->server.protocol >= PROTOCOL_LANMAN1 && !f->server->server.prefer_core_protocol)
	{
		QUAD position_quad = (*offset);
		int max_readx_size;
		int count;

		/* Calculate the maximum number of bytes that could be transferred with
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

			result = smb_proc_readx (&f->server->server, &f->dirent, &position_quad, count, data, error_ptr);
			if (result < 0)
				goto out;

			num_bytes_read += result;
			len -= result;
			add_64_plus_32_to_64(&position_quad,result,&position_quad);
			data += result;

			if(result < count)
			{
				LOG(("read returned fewer characters than expected (%ld < %ld)\n",result,count));
				break;
			}
		}
		while (len > 0);
	}
	/* SMB_COM_READ_RAW and SMB_COM_WRITE_RAW supported? */
	else if ((f->server->server.capabilities & CAP_RAW_MODE) != 0)
	{
		int max_raw_size = f->server->server.max_raw_size;
		QUAD position_quad = (*offset);
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

			result = smb_proc_read_raw (&f->server->server, &f->dirent, &position_quad, n, data, error_ptr);
			if(result <= 0)
			{
				LOG(("!!! wanted to read %ld bytes, got %ld\n",n,result));
				break;
			}

			num_bytes_read += result;
			len -= result;
			add_64_plus_32_to_64(&position_quad,result,&position_quad);
			data += result;

			if(result < n)
			{
				LOG(("read returned fewer characters than expected (%ld < %ld)\n",result,n));
				break;
			}
		}
		while(len > 0);
	}
	else
	{
		int max_size_smb_com_read;
		off_t position = offset->Low;
		int count;

		/* Calculate the maximum number of bytes that could be transferred with
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

			result = smb_proc_read (&f->server->server, &f->dirent, position, count, data, error_ptr);
			if (result < 0)
				goto out;

			num_bytes_read += result;
			len -= result;
			position += result;
			data += result;

			if(result < count)
			{
				LOG(("read returned fewer characters than expected (%ld < %ld)\n",result,count));
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
smba_write (smba_file_t * f, const char *data, long len, const QUAD * const offset, int * error_ptr)
{
	int num_bytes_written = 0;
	int max_buffer_size;
	int result;

	result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	D(("maximum buffer size = %ld\n", f->server->server.max_buffer_size));

	max_buffer_size = f->server->server.max_buffer_size;

	/* SMB_COM_WRITE_ANDX supported? */
	if (f->server->server.protocol >= PROTOCOL_LANMAN1 && !f->server->server.prefer_core_protocol)
	{
		QUAD position_quad = (*offset);
		int max_writex_size;
		int n;

		/* Calculate the maximum number of bytes that could be transferred with
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

			LOG(("writing %ld bytes; offset=%s, len=%ld\n", n, convert_quad_to_string(&position_quad), len));

			result = smb_proc_writex(&f->server->server, &f->dirent, &position_quad, n, data, error_ptr);
			if(result < 0)
				goto out;

			LOG(("number of bytes written = %ld\n", result));

			data += result;
			add_64_plus_32_to_64(&position_quad,result,&position_quad);
			len -= result;
			num_bytes_written += result;
		}
		while(len > 0);
	}
	else if ((f->server->server.capabilities & CAP_RAW_MODE) != 0)
	{
		int max_raw_size = f->server->server.max_raw_size;
		int max_size_smb_com_write_raw;
		QUAD position_quad = (*offset);
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
		 * 2(dataoffset)+4(offset high) = 29 bytes
		 *
		 * The data part of a SMB_COM_WRITE_RAW command accounts for
		 * 2(bytecount) = 2 bytes
		 *
		 * This leaves 'max_buffer_size' - 63 for the payload.
		 */
		max_size_smb_com_write_raw = max(max_buffer_size, max_raw_size) - 63;

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

			result = smb_proc_write_raw (&f->server->server, &f->dirent, &position_quad, n, data, error_ptr);
			if(result < 0)
				goto out;

			data += result;
			add_64_plus_32_to_64(&position_quad,result,&position_quad);
			len -= result;
			num_bytes_written += result;
		}
		while(len > 0);
	}
	else
	{
		int max_size_smb_com_write, count;
		off_t position = offset->Low;

		/* Calculate the maximum number of bytes that could be transferred with
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

			result = smb_proc_write (&f->server->server, &f->dirent, position, count, data, error_ptr);
			if (result < 0)
				goto out;

			len -= result;
			position += result;
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

	/* Even if one write access failed, we may have succeeded
	 * at writing some data. Hence we update the cached file
	 * size here and take note of the change made.
	 */
	if(num_bytes_written > 0)
	{
		QUAD size_quad;
		QUAD new_position_quad;

		/* This file was modified. */
		f->dirent.mtime = get_current_time();

		size_quad.Low	= f->dirent.size_low;
		size_quad.High	= f->dirent.size_high;

		add_64_plus_32_to_64(offset,num_bytes_written,&new_position_quad);

		if(compare_64_to_64(&new_position_quad,&size_quad) > 0)
		{
			f->dirent.size_low	= new_position_quad.Low;
			f->dirent.size_high	= new_position_quad.High;
		}
	}

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

	memset(rec_lock, 0, sizeof(*rec_lock));

	rec_lock->offset = offset,
	rec_lock->len = len;

	result = smb_proc_lockingX (&f->server->server, &f->dirent, rec_lock, 1, mode, timeout, error_ptr);

 out:

	if(rec_lock != NULL)
		free (rec_lock);

	return(result);
}

/*****************************************************************************/

static void
copy_dirent_to_stat_data(smba_stat_t * data, const struct smb_dirent * dirent)
{
	ASSERT( data != NULL && dirent != NULL );

	data->is_dir							= (dirent->attr & SMB_FILE_ATTRIBUTE_DIRECTORY) != 0;
	data->is_read_only						= (dirent->attr & SMB_FILE_ATTRIBUTE_READONLY) != 0;
	data->is_hidden							= (dirent->attr & SMB_FILE_ATTRIBUTE_HIDDEN) != 0;
	data->is_system							= (dirent->attr & SMB_FILE_ATTRIBUTE_SYSTEM) != 0;
	data->was_changed_since_last_archive	= (dirent->attr & SMB_FILE_ATTRIBUTE_ARCHIVE) != 0;

	data->size_low	= dirent->size_low;
	data->size_high	= dirent->size_high;

	data->atime = dirent->atime;
	data->ctime = dirent->ctime;
	data->mtime = dirent->mtime;
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

	now = get_current_time();

	if (file_attributes_are_stale (now, f))
	{
		LOG (("file '%s' attributes %s\n",
			escape_name(f->dirent.complete_path),
			(f->attr_time == 0) ? "are not yet known" : "need to be updated"
		));

		if (!f->server->server.prefer_core_protocol && f->server->server.protocol >= PROTOCOL_LANMAN2)
		{
			LOG(("using the LAN Manager 2.0 path query variant\n"));

			if (f->dirent.opened)
				result = smb_query_path_information (&f->server->server, NULL, 0, f->dirent.fileid, &f->dirent, error_ptr);
			else
				result = smb_query_path_information (&f->server->server, f->dirent.complete_path, f->dirent.len, 0, &f->dirent, error_ptr);
		}
		else
		{
			LOG(("using the legacy path query variant\n"));

			if (f->dirent.opened && f->server->supports_E)
			{
				LOG(("using smb_proc_getattrE\n"));

				result = smb_proc_getattrE (&f->server->server, &f->dirent, error_ptr);
			}
			else
			{
				LOG(("using smb_proc_getattr_core\n"));

				result = smb_proc_getattr_core (&f->server->server, f->dirent.complete_path, f->dirent.len, &f->dirent, error_ptr);
			}
		}

		if (result < 0)
			goto out;

		f->attr_time = now;
	}

	copy_dirent_to_stat_data(data, &f->dirent);

 out:

	return(result);
}

/*****************************************************************************/

int
smba_setattr (smba_file_t * f, const smba_stat_t * st, const QUAD * const size, int * error_ptr)
{
	BOOL times_changed = FALSE;
	int result = 0;
	dword attrs;

	if (st != NULL)
	{
		if (st->atime != 0 && st->atime != (time_t)-1 && f->dirent.atime != st->atime)
		{
			LOG(("atime changed to %lu\n",st->atime));

			f->dirent.atime = st->atime;
			times_changed = TRUE;
		}

		if (st->ctime != 0 && st->ctime != (time_t)-1 && f->dirent.ctime != st->ctime)
		{
			LOG(("ctime changed to %lu\n",st->ctime));

			f->dirent.ctime = st->ctime;
			times_changed = TRUE;
		}

		if (st->mtime != 0 && st->mtime != (time_t)-1 && f->dirent.mtime != st->mtime)
		{
			LOG(("mtime changed to %lu\n",st->mtime));

			f->dirent.mtime = st->mtime;
			times_changed = TRUE;
		}

		attrs = f->dirent.attr;

		if (st->is_read_only)
			attrs |= SMB_FILE_ATTRIBUTE_READONLY;
		else
			attrs &= ~SMB_FILE_ATTRIBUTE_READONLY;

		if (st->was_changed_since_last_archive)
			attrs |= SMB_FILE_ATTRIBUTE_ARCHIVE;
		else
			attrs &= ~SMB_FILE_ATTRIBUTE_ARCHIVE;

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

	if (size != NULL && (size->Low != f->dirent.size_low || size->High != f->dirent.size_high))
	{
		result = make_open (f, open_need_fid, open_writable, open_dont_truncate, error_ptr);
		if(result < 0)
			goto out;

		if(!f->server->server.prefer_core_protocol && f->server->server.protocol >= PROTOCOL_LANMAN2)
		{
			LOG(("using the LAN Manager 2.0 trunc variant\n"));

			result = smb_set_file_information (&f->server->server, &f->dirent, size, error_ptr);
		}
		else
		{
			LOG(("using the legacy trunc variant (which cannot truncate files)\n"));

			result = smb_proc_trunc (&f->server->server, &f->dirent, size->Low, error_ptr);
		}

		if(result < 0)
			goto out;

		f->dirent.size_low	= size->Low;
		f->dirent.size_high	= size->High;
	}

 out:

	return(result);
}

/*****************************************************************************/

int
smba_readdir (smba_file_t * f, int offs, void *callback_data, smba_callback_t callback, int * eof_ptr, int * error_ptr)
{
	const struct smb_dirent * dirent;
	int cache_index, o, eof, count = 0;
	int num_entries;
	smba_stat_t data;
	int result;
	ULONG now;

	if(eof_ptr != NULL)
		(*eof_ptr) = FALSE;

	result = make_open (f, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	now = get_current_time();

	/* get a cache for this directory unless we already have one */
	if (f->dircache == NULL)
	{
		dircache_t * dircache;

		/* Grab the least recently used cache table entry, which
		 * should sit at the end of the list.
		 */
		dircache = (dircache_t *)f->server->dircache_list.mlh_TailPred;

		/* Is the cache currently in use? */
		if (dircache->cache_for != NULL)
		{
			LOG(("stealing cache from '%s'\n", escape_name(dircache->cache_for->dirent.complete_path)));

			/* Steal the cache from the other directory? */
			dircache->cache_for->dircache = NULL;
		}

		reset_dircache(dircache);

		dircache->cache_for = f;
		f->dircache = dircache;
	}
	else
	{
		/* Has the cache already become stale? */
		if (dircache_has_expired(now, f->dircache))
		{
			LOG (("cache for '%s' has become stale\n", escape_name(f->dircache->cache_for->dirent.complete_path)));

			reset_dircache(f->dircache);
		}
	}

	/* Make sure that the cache is not easily stolen. */
	if (f->server->dircache_list.mlh_Head != &f->dircache->min_node)
	{
		Remove((struct Node *)f->dircache);
		AddHead((struct List *)&f->server->dircache_list, (struct Node *)f->dircache);
	}

	/* Read each single directory entry, drawing upon the
	 * cache contents, if possible.
	 */
	for (cache_index = offs ; ; cache_index++)
	{
		/* Nothing more to be read? */
		if (cache_index >= f->dircache->base + f->dircache->cache_used && f->dircache->eof)
			break;

		/* Is this entry not in the cache? */
		if (cache_index < f->dircache->base || cache_index >= f->dircache->base + f->dircache->cache_used)
		{
			LOG (("cachefill for '%s'\n", escape_name(f->dirent.complete_path)));
			LOG (("\tbase was: %ld, len was: %ld, newbase=%ld\n", f->dircache->base, f->dircache->cache_used, cache_index));

			/* Start over and read the next entries, beginning with
			 * entry at offset 'cache_index'.
			 */
			f->dircache->cache_used = 0;
			f->dircache->base = cache_index;

			/* Try to read up as many entries as will fit into
			 * the cache (cache_size).
			 */
			num_entries = smb_proc_readdir (&f->server->server, f->dirent.complete_path, cache_index, f->dircache, &eof, error_ptr);

			/* We stop on error, or if the directory is empty. */
			if (num_entries <= 0)
			{
				if (num_entries == 0)
					LOG(("no directory entries read\n"));

				result = num_entries;
				goto out;
			}

			/* The cache may have been invalidated because an error
			 * occured (e.g. server connection was terminated), or if
			 * the cache size was changed.
			 */
			if (f->dircache == NULL || !f->dircache->is_valid)
			{
				LOG (("dircache was invalidated, bailing out!\n"));

				(*error_ptr) = ENOENT;

				result = -1;
				goto out;
			}

			/* f->dircache->cache_used = num_entries; */
			f->dircache->eof = eof;
			f->dircache->created_at = now;

			LOG (("cachefill with %ld entries\n", num_entries));
		}

		o = cache_index - f->dircache->base;

		/* Is this the last directory entry to be delivered? */
		eof = (o >= (f->dircache->cache_used - 1) && f->dircache->eof);
		if(eof && eof_ptr != NULL)
			(*eof_ptr) = TRUE;

		count++;

		dirent = &f->dircache->cache[o];

		LOG (("delivering '%s', cache_index=%ld, last entry=%s\n",
			escape_name(dirent->complete_path),
			cache_index,
			eof ? "yes" : "no")
		);

		copy_dirent_to_stat_data(&data, dirent);

		if ((*callback) (callback_data, cache_index, cache_index + 1, dirent->complete_path, eof, &data))
			break;
	}

	result = count;

 out:

	return result;
}

/*****************************************************************************/

static char *
allocate_path_name(const smba_file_t * dir, const char *name, size_t * path_name_len_ptr)
{
	size_t dir_len = dir->dirent.len;
	char * path;
	size_t len;

	len = strlen(name);

	path = malloc (dir_len + 1 + len + 1);
	if(path != NULL)
	{
		memcpy (path, dir->dirent.complete_path, dir_len);
		path[dir_len++] = DOS_PATHSEP;
		memcpy(&path[dir_len], name, len+1); /* length includes terminating NUL character */

		ASSERT( path_name_len_ptr != NULL );

		(*path_name_len_ptr) = dir_len + len;
	}

	return(path);
}

/*****************************************************************************/

int
smba_create (smba_file_t * dir, const char *name, int truncate, int * error_ptr)
{
	struct smb_dirent entry;
	int ignored_error;
	char *path = NULL;
	size_t path_len = 0;
	int result;

	result = make_open (dir, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	memset (&entry, 0, sizeof (entry));

	entry.atime = entry.mtime = entry.ctime = get_current_time();

	path = allocate_path_name(dir, name, &path_len);
	if(path == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	if (!dir->server->server.prefer_core_protocol && dir->server->server.protocol >= PROTOCOL_LANMAN2)
	{
		LOG(("using the LAN Manager 2.0 creat variant\n"));

		result = smb_proc_open (&dir->server->server, path, path_len, open_writable, truncate, &entry, error_ptr);
		if(result < 0)
			goto out;
	}
	else
	{
		LOG(("using the legacy creat variant\n"));

		result = smb_proc_create (&dir->server->server, path, path_len, &entry, error_ptr);
		if(result < 0)
			goto out;
	}

	/* Close the file again, we don't really need it right now.
	 * Don't change the modification time.
	 */
	smb_proc_close(&dir->server->server,entry.fileid,-1,&ignored_error);

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
	size_t path_len = 0;
	int result;

	result = make_open (dir, open_dont_need_fid, open_read_only, open_dont_truncate, error_ptr);
	if (result < 0)
		goto out;

	path = allocate_path_name(dir, name, &path_len);
	if(path == NULL)
	{
		(*error_ptr) = ENOMEM;

		result = -1;
		goto out;
	}

	result = smb_proc_mkdir (&dir->server->server, path, path_len, error_ptr);
	if(result < 0)
		goto out;

 out:

	if(path != NULL)
		free (path);

	return(result);
}

/*****************************************************************************/

/* Mark a file/directory as no longer valid, closing it if necessary. */
static int
invalidate_smba_file(smba_server_t * s, smba_file_t *f, const char *path, int * error_ptr)
{
	int result = 0;

	if (f->dirent.opened)
	{
		/* Don't change the modification time. */
		result = smb_proc_close (&s->server, f->dirent.fileid, -1, error_ptr);
		if(result < 0)
		{
			LOG(("closing '%s' with file id %ld failed\n", escape_name(path), f->dirent.fileid));
			goto out;
		}

		f->dirent.opened = FALSE;
	}

	f->is_valid = FALSE;

 out:

	return(result);
}

/*****************************************************************************/

static int
close_path (smba_server_t * s, const char *path, int * error_ptr)
{
	int result = 0;
	smba_file_t *p;

	#ifndef USE_SPLAY_TREE
	{
		for (p = (smba_file_t *)s->open_files.mlh_Head;
			p->node.mln_Succ != NULL;
			p = (smba_file_t *)p->node.mln_Succ)
		{
			if (p->is_valid && compare_names(p->dirent.complete_path, path) == SAME)
			{
				result = invalidate_smba_file(s, p, path, error_ptr);
				if(result < 0)
					break;
			}
		}
	}
	#else
	{
		struct splay_node * sn;

		/* Find all files which match the same path name. */
		sn = splay_tree_find(&s->open_file_name_tree, (splay_key_t)path);
		if(sn != NULL)
		{
			/* Walk through all the files, marking them as no longer
			 * valid and closing them, if necessary. Note that we
			 * do not remove them from the list of open files, we just
			 * mark them for reopening later, if needed.
			 */
			for((void)NULL ; sn != NULL ; sn = sn->sn_next)
			{
				p = sn->sn_userdata;

				if (p->is_valid)
				{
					result = invalidate_smba_file(s, p, path, error_ptr);
					if(result < 0)
						break;
				}
			}
		}
	}
	#endif /* USE_SPLAY_TREE */

	return(result);
}

/*****************************************************************************/

int
smba_remove (smba_server_t * s, const char *path, int * error_ptr)
{
	int result;

	result = close_path (s, path, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_unlink (&s->server, path, strlen (path), error_ptr);
	if(result < 0)
		goto out;

 out:

	return result;
}

/*****************************************************************************/

int
smba_rmdir (smba_server_t * s, const char *path, int * error_ptr)
{
	int result;

	result = close_path (s, path, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_rmdir (&s->server, path, strlen (path), error_ptr);
	if(result < 0)
		goto out;

 out:

	return result;
}

/*****************************************************************************/

int
smba_rename (smba_server_t * s, const char *from, const char *to, int * error_ptr)
{
	int result;

	result = close_path (s, from, error_ptr);
	if(result < 0)
		goto out;

	result = smb_proc_mv (&s->server, from, strlen (from), to, strlen (to), error_ptr);
	if(result < 0)
		goto out;

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
smba_invalidate_all_inodes (smba_server_t * server)
{
	dircache_t * dircache;
	smba_file_t *f;

	ENTER();

	ASSERT( server != NULL );

	for(dircache = (dircache_t *)server->dircache_list.mlh_Head ;
	    dircache->min_node.mln_Succ != NULL ;
	    dircache = (dircache_t *)dircache->min_node.mln_Succ)
	{
		invalidate_dircache(dircache);
	}

	for (f = (smba_file_t *)server->open_files.mlh_Head;
	     f->node.mln_Succ != NULL;
	     f = (smba_file_t *)f->node.mln_Succ)
	{
		f->dirent.opened	= FALSE;
		f->is_valid			= FALSE;
	}

	LEAVE();
}

/*****************************************************************************/

int
smba_get_dircache_size(struct smba_server * server)
{
	const dircache_t * dircache = (dircache_t *)server->dircache_list.mlh_Head;
	int result;

	result = dircache->cache_size;

	return(result);
}

/*****************************************************************************/

int
smba_change_dircache_size(struct smba_server * server, int cache_size)
{
	const dircache_t * old_dircache = (dircache_t *)server->dircache_list.mlh_Head;
	struct List new_dircache_list;
	dircache_t * dircache;
	int result;
	int i;

	ENTER();

	NewList(&new_dircache_list);

	result = old_dircache->cache_size;

	/* We have to have a minimum cache size. */
	if (cache_size < 10)
		cache_size = 10;

	/* Don't do anything if the cache size has not changed. */
	if (cache_size == old_dircache->cache_size)
		goto out;

	/* Allocate a new cache. */
	for(i = 0 ; i < server->dircache_list_size ; i++)
	{
		dircache = allocate_dircache(cache_size);
		if(dircache == NULL)
			goto out;

		AddTail(&new_dircache_list, (struct Node *)dircache);
	}

	/* Free the old cache. */
	while((dircache = (dircache_t *)RemHead((struct List *)&server->dircache_list)) != NULL)
		free_dircache(dircache);

	/* Put the new cache in place of the old cache. */
	while((dircache = (dircache_t *)RemHead(&new_dircache_list)) != NULL)
		AddTail((struct List *)&server->dircache_list, (struct Node *)dircache);

	result = cache_size;

 out:

	/* If allocating the new cache failed, clean up after
	 * the cache entries which we succeeded in creating.
	 */
	while((dircache = (dircache_t *)RemHead(&new_dircache_list)) != NULL)
		free_dircache(dircache);

	RETURN(result);
	return(result);
}

/*****************************************************************************/

static int
extract_service (
	const char *	service,
	char *			server,
	size_t			server_size,
	char *			tcp_service_name,
	size_t			tcp_service_name_size,
	char *			share,
	size_t			share_size,
	int *			error_ptr)
{
	char * share_start;
	char * root_start;
	char * complete_service;
	char * service_copy = NULL;
	char * service_name;
	int result = -1;

	if (strlen (service) < 4)
	{
		report_error("Service name '%s' is too short.",service);

		(*error_ptr) = EINVAL;

		goto out;
	}

	if (service[0] != '/')
	{
		report_error("Service name '%s' must begin with '/'.",service);

		(*error_ptr) = EINVAL;

		goto out;
	}

	service_copy = malloc(strlen(service)+1);
	if(service_copy == NULL)
	{
		report_error("Not enough memory.");

		(*error_ptr) = ENOMEM;

		goto out;
	}

	strcpy (service_copy, service);

	complete_service = service_copy;

	while (complete_service[0] == '/')
		complete_service++;

	share_start = strchr (complete_service, '/');
	if (share_start == NULL)
	{
		report_error("Share name '%s' must contain a '/'.",complete_service);

		(*error_ptr) = EINVAL;

		goto out;
	}

	(*share_start++) = '\0';
	root_start = strchr (share_start, '/');

	if (root_start != NULL)
		(*root_start) = '\0';

	/* Check if there's a port number encoded in the service name. */
	service_name = strchr(complete_service,':');
	if(service_name != NULL)
	{
		int len;

		/* Cut off the TCP service name, but remember where
		 * the name starts.
		 */
		(*service_name++) = '\0';

		/* Skip leading and trailing blank spaces, just to be safe. */
		while((*service_name) == ' ')
			service_name++;

		len = strlen(service_name);
		while(len > 0 && (*service_name) == ' ')
			len--;

		service_name[len] = '\0';

		if(len > tcp_service_name_size)
		{
			report_error("TCP service name/port number is too long in '%s' (%ld characters are possible).",service_name,tcp_service_name_size);

			(*error_ptr) = EINVAL;

			goto out;
		}
	}

	if (strlen (complete_service) > server_size)
	{
		report_error("Server name is too long in '%s' (%ld characters are possible).",service,server_size);

		(*error_ptr) = ENAMETOOLONG;

		goto out;
	}

	if (strlen (share_start) > share_size)
	{
		report_error("Share name is too long in '%s' (%ld characters are possible).",service,share_size);

		(*error_ptr) = ENAMETOOLONG;

		goto out;
	}

	strlcpy (server, complete_service, server_size);
	strlcpy (share, share_start, share_size);
	strlcpy (tcp_service_name, service_name != NULL ? service_name : "", tcp_service_name_size);

	result = 0;

 out:

	if(service_copy != NULL)
		free(service_copy);

	return(result);
}

/*****************************************************************************/

int
smba_start(
	const char *		service,
	const char *		opt_workgroup,
	const char *		opt_username,
	const char *		opt_password,
	const char *		opt_clientname,
	const char *		opt_servername,
	int					opt_cachesize,
	int					opt_cache_tables,
	int					opt_max_transmit,
	int					opt_timeout,
	int					opt_raw_smb,
	int					opt_unicode,
	int					opt_prefer_core_protocol,
	int					opt_case_sensitive,
	int					opt_session_setup_delay_unicode,
	int					opt_write_behind,
	int					opt_smb_request_write_threshold,
	int					opt_smb_request_read_threshold,
	int					opt_scatter_gather,
	int					opt_tcp_no_delay,
	int					opt_socket_receive_buffer_size,
	int					opt_socket_send_buffer_size,
	int *				error_ptr,
	int *				smb_error_class_ptr,
	int *				smb_error_ptr,
	smba_connect_parameters_t *
						smba_connect_par,
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
	char server[64], share[256], tcp_service_name[40];
	struct sockaddr_in server_ip_address;
	int result = -1;

	ASSERT( error_ptr != NULL );
	ASSERT( smb_error_class_ptr != NULL );
	ASSERT( smb_error_ptr != NULL );

	(*error_ptr) = (*smb_error_class_ptr) = (*smb_error_ptr) = 0;
	(*smba_server_ptr) = NULL;
	(*username) = (*password) = (*server_name) = (*client_name) = '\0';

	if(extract_service (service, server, sizeof(server), tcp_service_name, sizeof(tcp_service_name), share, sizeof(share), error_ptr) < 0)
		goto out;

	/* Use the workgroup name provided? */
	if (opt_workgroup != NULL)
	{
		strlcpy (workgroup, opt_workgroup, sizeof(workgroup));
		string_toupper (workgroup);
	}
	/* Use the default workgroup name instead. */
	else
	{
		strlcpy (workgroup, "WORKGROUP", sizeof(workgroup));
	}

	memset(&server_ip_address,0,sizeof(server_ip_address));
	server_ip_address.sin_family = AF_INET;

	server_ip_address.sin_addr.s_addr = inet_addr (server);
	if (server_ip_address.sin_addr.s_addr == INADDR_NONE) /* name was given, not numeric */
	{
		char * dot;
		int lookup_error;

		LOG(("server name is '%s'\n", server));

		h_errno = 0;

		h = gethostbyname (server);

		lookup_error = h_errno;

		if (h != NULL)
		{
			memcpy(&server_ip_address.sin_addr,h->h_addr,h->h_length);
		}
		else if (strlen(server) > 16 || BroadcastNameQuery(server,"",(UBYTE *)&server_ip_address.sin_addr) != 0)
		{
			if(lookup_error == 0)
				report_error("Could not look up network address of '%s' (%ld, %s).",server,errno,posix_strerror(errno));
			else
				report_error("Could not look up network address of '%s' (%ld, %s).",server,lookup_error,host_strerror(lookup_error));

			(*error_ptr) = ENOENT;
			goto out;
		}

		LOG(("server network address found (%s)\n", Inet_NtoA(server_ip_address.sin_addr.s_addr)));

		/* No workgroup given? Ask the server... */
		if(opt_workgroup == NULL)
		{
			char workgroup_name[16];

			if(SendNetBIOSStatusQuery(server_ip_address,NULL,0,workgroup_name,sizeof(workgroup_name)) == 0)
			{
				if(workgroup_name[0] != '\0')
					strlcpy (workgroup, workgroup_name, sizeof(workgroup));
			}
		}

		/* Remember the server name, retaining only the
		 * host name.
		 */
		strlcpy (server_name, server, sizeof(server_name));

		dot = strchr(server_name,'.');
		if(dot != NULL)
			(*dot) = '\0';
	}
	else
	{
		char host_name[MAXHOSTNAMELEN+1];
		char workgroup_name[16];
		const char * name;

		LOG(("server network address is %s\n", server));

		/* Ask the server about its name and its workgroup. We need to
		 * know the name to continue, and the workgroup name may
		 * be useful, too.
		 */
		if(SendNetBIOSStatusQuery(server_ip_address,server_name,sizeof(server_name),workgroup_name,sizeof(workgroup_name)) == 0 && server_name[0] != '\0')
		{
			LOG(("server %s provided its own name '%s', with workgroup '%s'\n",Inet_NtoA(server_ip_address.sin_addr.s_addr),server_name,workgroup_name));

			/* No workgroup given? Use what the server told us... */
			if(opt_workgroup == NULL && workgroup_name[0] != '\0')
				strlcpy (workgroup, workgroup_name, sizeof(workgroup));
		}
		else
		{
			h_errno = 0;

			h = gethostbyaddr ((char *) &server_ip_address.sin_addr.s_addr, sizeof (server_ip_address.sin_addr.s_addr), server_ip_address.sin_family);
			if (h == NULL)
			{
				if(h_errno == 0)
				{
					report_error("Could not look up name of server with network address %s (%ld, %s).",server,errno,posix_strerror(errno));

					if(errno != 0)
						(*error_ptr) = errno;
					else
						(*error_ptr) = ENOENT;
				}
				else
				{
					report_error("Could not look up name of server with network address %s (%ld, %s).",server,h_errno,host_strerror(h_errno));
					(*error_ptr) = ENOENT;
				}

				goto out;
			}

			name = h->h_name;

			LOG(("server host name found (%s)\n",name));

			/* Brian Willette: Now we will set the server name to the DNS
			 * hostname, hopefully this will be the same as the NetBIOS name for
			 * the server.
			 *
			 * We do this because the user supplied no hostname, and we
			 * need one for NetBIOS, this is the best guess choice we have
			 * NOTE: If the names are different between DNS and NetBIOS on
			 * the windows side, the user MUST use the -s option.
			 */
			for (i = 0; i < MAXHOSTNAMELEN && name[i] != '.' && name[i] != '\0' ; i++)
				host_name[i] = name[i];

			host_name[i] = '\0';

			/* Make sure the hostname is 16 characters or less (for NetBIOS) */
			if (!opt_raw_smb && strlen (host_name) > 16)
			{
				report_error("Server name '%s' is too long (%ld characters are possible).", host_name, 16);

				(*error_ptr) = ENAMETOOLONG;
				goto out;
			}

			strlcpy (server_name, host_name, sizeof(server_name));
		}
	}

	if(opt_password != NULL)
	{
		if(strlen(opt_password) >= sizeof(password))
		{
			report_error("Password is too long (%ld characters are possible).", sizeof(password)-1);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy(password,opt_password,sizeof(password));
	}

	if(strlen(opt_username) >= sizeof(username))
	{
		report_error("User name '%s' is too long (%ld characters are possible).", username,sizeof(username)-1);

		(*error_ptr) = ENAMETOOLONG;
		goto out;
	}

	strlcpy(username,opt_username,sizeof(username));

	if(opt_servername != NULL)
	{
		if (!opt_raw_smb && strlen (opt_servername) > 16)
		{
			report_error("Server name '%s' is too long (%ld characters are possible).", opt_servername,16);

			(*error_ptr) = ENAMETOOLONG;
			goto out;
		}

		strlcpy (server_name, opt_servername, sizeof(server_name));
	}

	if(opt_clientname != NULL)
	{
		if (!opt_raw_smb && strlen (opt_clientname) > 16)
		{
			report_error("Client name '%s' is too long (%ld characters are possible).", opt_clientname,16);

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

	LOG(("server name = '%s', client name = '%s', workgroup name = '%s', user name = '%s'\n",
		server_name, client_name, workgroup, username));

	if(smba_connect (
		&par,
		server_ip_address,
		tcp_service_name,
		use_extended,
		workgroup,
		opt_cachesize,
		opt_cache_tables,
		opt_max_transmit,
		opt_timeout,
		opt_raw_smb,
		opt_unicode,
		opt_prefer_core_protocol,
		opt_case_sensitive,
		opt_session_setup_delay_unicode,
		opt_write_behind,
		opt_smb_request_write_threshold,
		opt_smb_request_read_threshold,
		opt_scatter_gather,
		opt_tcp_no_delay,
		opt_socket_receive_buffer_size,
		opt_socket_send_buffer_size,
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

			report_error("Could not connect to server '%s' (%ld/%ld, %s/%s).",
				server,(*smb_error_class_ptr),(*smb_error_ptr),smb_class_name,smb_code_text);
		}
		else
		{
			report_error("Could not connect to server '%s' (%ld, %s).",
				server,(*error_ptr),posix_strerror(*error_ptr));
		}

		goto out;
	}

	if(smba_connect_par != NULL)
		(*smba_connect_par) = par;

	(*smba_server_ptr) = the_server;

	result = 0;

 out:

	return(result);
}
