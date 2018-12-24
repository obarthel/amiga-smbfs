/*
 * :ts=4
 *
 * Name: smb_abstraction.h
 * Description: Interface to the smb abstraction layer.
 * Author: Christian Starkjohann <cs -at- hal -dot- kph -dot- tuwien -dot- ac -dot- at>
 * Date: 1996-12-31
 * Copyright: GNU-GPL
 *
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 * Modified to support record locking by Peter Riede <Noster-Riede -at- T-Online -dot- de>
 */

#ifndef _SMB_ABSTRACTION_H
#define _SMB_ABSTRACTION_H 1

/****************************************************************************/

#include <time.h>

/****************************************************************************/

#ifndef _QUAD_MATH_H
#include "quad_math.h"
#endif /* _QUAD_MATH_H */

/****************************************************************************/

#ifndef _SPLAY_H
#include "splay.h"
#endif /* _SPLAY_H */

/*****************************************************************************/

#ifndef _SMB_FS_SB
#include <smb/smb_fs_sb.h>
#endif /* _SMB_FS_SB */

#ifndef _SMB_H
#include <smb/smb.h>
#endif /* _SMB_H */

/*****************************************************************************/

/* These should make the respective purpose of each make_open()
 * parameter clearer. The read/write and truncate options are
 * also used by smba_open().
 */
#define open_dont_need_fid	FALSE
#define open_need_fid		TRUE

#define open_read_only		FALSE
#define open_writable		TRUE

#define open_dont_truncate	FALSE
#define open_truncate		TRUE

/****************************************************************************/

typedef struct smba_connect_parameters
{
	char	server_ipname[64];
	char	service[64];
	char *	server_name;
	char *	client_name;
	char *	username;
	char *	password;
} smba_connect_parameters_t;

typedef struct smba_stat
{
	unsigned		is_dir:1;
	unsigned		is_read_only:1;
	unsigned		is_hidden:1;
	unsigned		is_system:1;
	unsigned		was_changed_since_last_archive:1;

	unsigned long	size_low;
	unsigned long	size_high;

	time_t			atime;
	time_t			ctime;
	time_t			mtime;
} smba_stat_t;

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

typedef struct smba_server
{
	struct smb_server	server;
	struct MinList		open_files;

	#ifdef USE_SPLAY_TREE

	struct splay_tree	open_file_address_tree;
	struct splay_tree	open_file_name_tree;

	#endif /* USE_SPLAY_TREE */

	ULONG				num_open_files;

	dircache_t *		dircache;

	unsigned			supports_E:1;
	unsigned			supports_E_known:1;
} smba_server_t;

typedef struct smba_file
{
	struct MinNode			node;

	#ifdef USE_SPLAY_TREE

	struct splay_node		splay_address_node;
	struct splay_node		splay_name_node;

	#endif /* USE_SPLAY_TREE */

	struct smba_server *	server;

	struct smb_dirent		dirent;
	ULONG					attr_time;		/* time when dirent was read */
	dircache_t *			dircache;		/* content cache for directories */

	unsigned				is_valid:1;		/* server was down, entry removed, ... */
	unsigned				attr_dirty:1;	/* attribute cache is dirty */
} smba_file_t;

/****************************************************************************/

typedef int (*smba_callback_t) (void *callback_data, int fpos, int nextpos, const char *name, int eof, const smba_stat_t * st);

/****************************************************************************/

void smba_disconnect(smba_server_t *server);
int smba_open(smba_server_t *s, const char *name, int writable, int truncate_file, smba_file_t **file, int *error_ptr);
void smba_close(smba_server_t *s, smba_file_t *f);
int smba_read(smba_file_t *f, char *data, long len, const QUAD *const offset, int *error_ptr);
int smba_write(smba_file_t *f, const char *data, long len, const QUAD *const offset, int *error_ptr);
int smba_lockrec(smba_file_t *f, long offset, long len, long mode, int unlocked, long timeout, int *error_ptr);
int smba_getattr(smba_file_t *f, smba_stat_t *data, int *error_ptr);
int smba_setattr(smba_file_t *f, const smba_stat_t *data, const QUAD *const size, int *error_ptr);
int smba_readdir(smba_file_t *f, int offs, void *callback_data, smba_callback_t callback, int *error_ptr);
int smba_create(smba_file_t *dir, const char *name, int truncate, int *error_ptr);
int smba_mkdir(smba_file_t *dir, const char *name, int *error_ptr);
int smba_remove(smba_server_t *s, const char *path, int *error_ptr);
int smba_rmdir(smba_server_t *s, const char *path, int *error_ptr);
int smba_rename(smba_server_t *s, const char *from, const char *to, int *error_ptr);
int smba_statfs(smba_server_t *s, long *bsize, long *blocks, long *bfree, int *error_ptr);
void smb_invalidate_all_inodes(struct smb_server *server);
int smba_start(const char *service, const char *opt_workgroup, const char *opt_username, const char *opt_password, const char *opt_clientname, const char *opt_servername, int opt_cachesize, int opt_max_transmit, int opt_timeout, int opt_raw_smb, int opt_unicode, int opt_prefer_core_protocol, int opt_case_sensitive, int opt_session_setup_delay_unicode, int opt_write_behind, int opt_smb_request_write_threshold, int opt_smb_request_read_threshold, int opt_tcp_no_delay, int opt_socket_receive_buffer_size, int opt_socket_send_buffer_size, int *error_ptr, int *smb_error_class_ptr, int *smb_error_ptr, smba_connect_parameters_t *smba_connect_par, smba_server_t **smba_server_ptr);
int smba_get_dircache_size(struct smba_server *server);
int smba_change_dircache_size(struct smba_server *server, int cache_size);

/****************************************************************************/

#endif /* _SMB_ABSTRACTION_H */
