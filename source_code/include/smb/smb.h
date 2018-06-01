/*
 * :ts=4
 *
 * smb.h
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#ifndef _SMB_H
#define _SMB_H

#define SMB_MAXNAMELEN 255

typedef unsigned char	byte;
typedef unsigned short	word;
typedef unsigned long	dword;

/*
 * Set/Get values in SMB-byte order
 */

#define PVAL(buf,pos)		((unsigned)BVAL(buf,pos))

#define BVAL(buf,pos)		(((unsigned char *)(buf))[pos])
#define WVAL(buf,pos)		(((word)PVAL(buf,pos))|((word)PVAL(buf,(pos)+1))<<8)
#define DVAL(buf,pos)		(((dword)WVAL(buf,pos))|((dword)WVAL(buf,(pos)+2))<<16)

#define BSET(buf,pos,val)	(BVAL(buf,pos)=((val) & 0xFF))
#define WSET(buf,pos,val)	do { BVAL(buf,pos)=((val) & 0xFF); BVAL(buf,(pos)+1)=(((unsigned)(val))>>8) & 0xFF; } while (0)
#define DSET(buf,pos,val)	do { WSET(buf,pos,(val)); WSET(buf,(pos)+2,((unsigned)(val))>>16); } while (0)

#define smb_base(buf)	((byte *)(((byte *)(buf))+4))

enum smb_protocol
{
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1
};

enum smb_conn_state
{
	CONN_VALID,		/* everything's fine */
	CONN_INVALID,	/* Something went wrong, but did not
					   try to reconnect yet. */
	CONN_RETRIED	/* Tried a reconnection, but was refused */
};

struct smb_dskattr
{
	dword total;
	dword allocblocks;
	dword blocksize;
	dword free;
};

/*
 * Contains all relevant data on a SMB networked file.
 */
struct smb_dirent
{
	word			fileid;					/* What id to handle a file with? */
	dword			attr;					/* Attribute fields, DOS value */

	time_t			atime, mtime, 
					wtime, ctime;			/* Times, as seen by the server, normalized
											 * to UTC. The ugly conversion happens in
											 * proc.c
											 */

	dword			size_low;				/* File size (least significant 32 bits). */
	dword			size_high;				/* File size (most significant 32 bits). */

	char *			complete_path;			/* Complete path, MS-DOS notation, with '\' */
	size_t			complete_path_size;		/* Number of bytes allocated for name; this is
											 * used only by the directory reader and
											 * the cache.
											 */

	int				len;					/* Name length. */

	unsigned		opened:1;				/* is it open on the fileserver? */
	unsigned		writable:1;				/* was opened for read/write access? */
};

#endif /* _SMB_H */
