/*
 * :ts=4
 *
 * smb_fs.h
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 * Modified for supporting SMBlockingX packets by Peter Riede <Noster-Riede -at- T-Online -dot- de>
 */

#ifndef _SMB_FS_H_SMB_H
#define _SMB_FS_H_SMB_H

#ifndef _SMB_H
#include <smb/smb.h>
#endif /* _SMB_H */

#ifndef _SMB_MOUNT_H
#include <smb/smb_mount.h>
#endif /* _SMB_MOUNT_H */

#ifndef _SMB_FS_SB
#include <smb/smb_fs_sb.h>
#endif /* _SMB_FS_SB */

#include <netinet/in.h>

#ifndef _QUAD_MATH_H
#include "quad_math.h"
#endif /* _QUAD_MATH_H */

/* This structure is used to pass the arguments to smb_proc_lockingX */
struct smb_lkrng
{
	off_t	offset;		/* offset to first byte to be (un)locked */
	long 	len;		/* bytesize of the block */
};

/* Macros to get at offsets within smb_lkrng and smb_unlkrng
   structures. We cannot define these as actual structures
   due to possible differences in structure packing
   on different machines/compilers. */

#define SMB_LPID_OFFSET(indx)				(10 * (indx))
#define SMB_LKOFF_OFFSET(indx)				( 2 + (10 * (indx)))
#define SMB_LKLEN_OFFSET(indx)				( 6 + (10 * (indx)))
#define SMB_LARGE_LKOFF_OFFSET_HIGH(indx)	(4 + (20 * (indx)))
#define SMB_LARGE_LKOFF_OFFSET_LOW(indx)	(8 + (20 * (indx)))
#define SMB_LARGE_LKLEN_OFFSET_HIGH(indx)	(12 + (20 * (indx)))
#define SMB_LARGE_LKLEN_OFFSET_LOW(indx)	(16 + (20 * (indx)))

/*****************************************************************************/

/* proc.c */
byte *smb_encode_smb_length(byte *p, int len);
int smb_len(const byte *packet);
void smb_translate_error_class_and_code(int errcls,int error,char ** class_ptr,char ** code_ptr);
int smb_errno(int errcls, int error);
int smb_payload_size(const struct smb_server *server, int wct, int bcc);
int smb_proc_open(struct smb_server *server, const char *pathname, int len, int writable, int truncate, struct smb_dirent *entry, int * error_ptr);
int smb_proc_close(struct smb_server *server, word fileid, dword mtime, int * error_ptr);
int smb_proc_read(struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, char *data, int * error_ptr);
int smb_proc_write (struct smb_server *server, struct smb_dirent *finfo, off_t offset, long count, const char *data, int * error_ptr);
int smb_proc_writex (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset, long count, const char *data, int * error_ptr);
int smb_proc_readx (struct smb_server *server, struct smb_dirent *finfo, const QUAD * const offset, long count, char *data, int * error_ptr);
int smb_proc_lockingX (struct smb_server *server, struct smb_dirent *finfo, const struct smb_lkrng *locks, int num_entries, int mode, long timeout, int * error_ptr);
int smb_proc_create(struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr);
int smb_proc_mv(struct smb_server *server, const char *opath, const int olen, const char *npath, const int nlen, int * error_ptr);
int smb_proc_mkdir(struct smb_server *server, const char *path, const int len, int * error_ptr);
int smb_proc_rmdir(struct smb_server *server, const char *path, const int len, int * error_ptr);
int smb_proc_unlink(struct smb_server *server, const char *path, const int len, int * error_ptr);
int smb_proc_trunc(struct smb_server *server, word fid, dword length, int * error_ptr);
int smb_proc_readdir(struct smb_server *server, const char *path, int fpos, int cache_size, struct smb_dirent *entry, int * error_ptr);
int smb_proc_getattr_core(struct smb_server *server, const char *path, int len, struct smb_dirent *entry, int * error_ptr);
int smb_proc_getattrE(struct smb_server *server, struct smb_dirent *entry, int * error_ptr);
int smb_query_path_information(struct smb_server *server, const char *path, int len, int fid, struct smb_dirent *entry, int * error_ptr);
int smb_set_file_information(struct smb_server *server, struct smb_dirent *entry, const QUAD * const size, int * error_ptr);
int smb_proc_setattr_core(struct smb_server *server, const char *path, int len, const struct smb_dirent *new_finfo, int * error_ptr);
int smb_proc_setattrE(struct smb_server *server, word fid, struct smb_dirent *new_entry, int * error_ptr);
int smb_proc_dskattr (struct smb_server *server, struct smb_dskattr *attr, int * error_ptr);
int smb_proc_connect(struct smb_server *server, int * error_ptr);

/* sock.c */
int smb_discard_netbios_frames(struct smb_server *server, int sock_fd, int * error_ptr);
void smb_check_server_connection(struct smb_server *server, int error);
void smb_release(struct smb_server *server);
int smb_connect(struct smb_server *server, int * error_ptr);
int smb_request(struct smb_server *server, int command, void * input_payload,const void * output_payload,int payload_size, int * error_ptr);
int smb_trans2_request(struct smb_server *server, int command, int *data_len, int *param_len, char **data, char **param, int * error_ptr);

#endif /* _SMB_FS_H_SMB_H */
