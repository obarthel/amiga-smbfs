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

/* Forward declaration to keep the compiler happy. */
#ifndef _SMB_FS_SB
struct smb_server;
#endif /* _SMB_FS_SB */

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
	char server_ipname[64];
	char service[64];
	char *server_name;
	char *client_name;
	char *username;
	char *password;
} smba_connect_parameters_t;

typedef struct smba_stat
{
	unsigned is_dir:1;
	unsigned is_wp:1;
	unsigned is_hidden:1;
	unsigned is_system:1;
	unsigned is_archive:1;
	int size;
	long atime;
	long ctime;
	long mtime;
} smba_stat_t;

/****************************************************************************/

typedef struct smba_server smba_server_t;
typedef struct smba_file smba_file_t;

/****************************************************************************/

typedef int (*smba_callback_t) (void *d, int fpos, int nextpos, char *name, int eof, smba_stat_t * st);

/****************************************************************************/

int smba_open(smba_server_t *s, char *name, size_t name_size, int writable, int truncate, smba_file_t **file, int * error_ptr);
void smba_close(smba_file_t *f, int * error_ptr);
int smba_read(smba_file_t *f, char *data, long len, long offset, int * error_ptr);
int smba_write(smba_file_t *f, const char *data, long len, long offset, int * error_ptr);
int smba_lockrec (smba_file_t *f, long offset, long len, long mode, int unlocked, long timeout, int * error_ptr);
int smba_getattr(smba_file_t *f, smba_stat_t *data, int * error_ptr);
int smba_setattr(smba_file_t *f, const smba_stat_t *data, const unsigned long * size_ptr, int * error_ptr);
int smba_readdir(smba_file_t *f, long offs, void *d, smba_callback_t callback, int * error_ptr);
int smba_create(smba_file_t *dir, const char *name, smba_stat_t *attr, int * error_ptr);
int smba_mkdir(smba_file_t *dir, const char *name, int * error_ptr);
int smba_remove(smba_server_t *s, char *path, int * error_ptr);
int smba_rmdir(smba_server_t *s, char *path, int * error_ptr);
int smba_rename(smba_server_t *s, char *from, char *to, int * error_ptr);
int smba_statfs(smba_server_t *s, long *bsize, long *blocks, long *bfree, int * error_ptr);
void smb_invalidate_all_inodes(struct smb_server *server);
int smba_start(char *service, char *opt_workgroup, char *opt_username, char *opt_password, char *opt_clientname, char *opt_servername, int opt_cachesize, int opt_max_transmit, int opt_timeout, int opt_raw_smb, int opt_write_behind, int opt_prefer_write_raw, int opt_disable_write_raw, int opt_disable_read_raw, char * opt_native_os, int * error_ptr, int * smb_error_class_ptr, int * smb_error_ptr, smba_server_t **result);
void smba_disconnect(smba_server_t *server);
int smba_get_dircache_size(struct smba_server * server);
int smba_change_dircache_size(struct smba_server * server,int cache_size);

/****************************************************************************/

#endif /* _SMB_ABSTRACTION_H */
