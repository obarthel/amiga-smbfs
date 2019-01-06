/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2018 by Olaf `Olsen' Barthel <obarthel -at- gmx -dot- net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _SMBFS_H
#define _SMBFS_H 1

/****************************************************************************/

#ifndef _SYSTEM_HEADERS_H
#include "system_headers.h"
#endif /* _SYSTEM_HEADERS_H */

#ifndef _ASSERT_H
#include "assert.h"
#endif /* _ASSERT_H */

#ifndef _QUAD_MATH_H
#include "quad_math.h"
#endif /* _QUAD_MATH_H */

#ifndef _SPLAY_H
#include "splay.h"
#endif /* _SPLAY_H */

/****************************************************************************/

#define SAME (0)
#define OK (0)
#define CANNOT !
#define NOT !
#define NO !
#define NOTHING ((void)0)

/****************************************************************************/

#ifndef ZERO
#define ZERO ((BPTR)NULL)
#endif /* ZERO */

/****************************************************************************/

#ifndef AMIGA_COMPILER_H

/****************************************************************************/

#if defined(__SASC)
#define FAR __far
#define ASM __asm
#define REG(r,p) register __##r p
#define INLINE __inline
#define STDARGS __stdargs
#endif /* __SASC */

#if defined(__GNUC__)
#define FAR
#define ASM
#define REG(r,p) p __asm(#r)
#define INLINE __inline__
#define STDARGS
#endif /* __GNUC__ */

/****************************************************************************/

#ifndef VARARGS68K
#define VARARGS68K
#endif /* VARARGS68K */

/*****************************************************************************/

#endif /* AMIGA_COMPILER_H */

/*****************************************************************************/

/* smbfs file system signature (SMB\0), as suggested by Chris Handley
 * and Chris Young.
 */
#define ID_SMB_DISK 0x534D4200

/*****************************************************************************/

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif /* min */

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif /* max */

/****************************************************************************/

#if defined(__SASC)
extern struct Library * FAR AbsExecBase;
#else
#ifndef AbsExecBase
#define AbsExecBase (*(struct Library **)4)
#endif /* AbsExecBase */
#endif /* __SASC */

/****************************************************************************/

extern struct Library * SocketBase;
extern struct Library * SysBase;
extern struct Library * DOSBase;

/****************************************************************************/

#if defined(__amigaos4__)

/****************************************************************************/

extern struct ExecIFace *	IExec;
extern struct DOSIFace *	IDOS;
extern struct SocketIFace *	ISocket;

/****************************************************************************/

#endif /* __amigaos4__ */

/****************************************************************************/

extern int h_errno;

/****************************************************************************/

extern int BroadcastNameQuery(const char *name, const char *scope, UBYTE *address);
extern int SendNetBIOSStatusQuery(struct sockaddr_in sox,char * server_name,int server_name_size,char * workgroup_name,int workgroup_name_size);
extern LONG compare_names(const TEXT * a,const TEXT * b);
extern LONG get_time_zone_delta(void);
extern STRPTR posix_strerror(int error);
extern STRPTR host_strerror(int error);
extern time_t tm_to_seconds(const struct tm * const tm);
extern ULONG get_current_time(void);
extern void seconds_to_tm(time_t seconds,struct tm * tm);
extern void VARARGS68K report_error(const TEXT * fmt,...);
extern void string_toupper(STRPTR s);
extern void VARARGS68K LocalSNPrintf(STRPTR buffer, int limit, const TEXT * formatString,...);
extern TEXT * escape_name(const TEXT * name);
extern const char * convert_quad_to_string(const QUAD * number);

/****************************************************************************/

size_t strlcpy(char *dst, const char *src, size_t siz);
size_t strlcat(char *dst, const char *src, size_t siz);

/****************************************************************************/

extern void smb_encrypt(const unsigned char *passwd, const unsigned char *c8, unsigned char *p24);
extern void smb_nt_encrypt(const unsigned char *passwd, const unsigned char *c8, unsigned char *p24);

/****************************************************************************/

extern void free_memory(APTR address);
extern APTR allocate_memory(LONG size);

#define malloc(s) allocate_memory(s)
#define free(m) free_memory(m)

/****************************************************************************/

#undef memcpy

#if defined (DEBUG)
	#define memcpy(to,from,size) \
		do \
		{ \
			ASSERT(((const char *)(to)) >= ((const char *)(from))+(size) || ((const char *)(from)) >= ((const char*)(to))+(size)); \
			CopyMem((APTR)(from),(APTR)(to),(ULONG)(size)); \
		} \
		while(0)
#else
#define memcpy(to,from,size) ((void)CopyMem((APTR)(from),(APTR)(to),(ULONG)(size)))
#endif /* DEBUG */

/****************************************************************************/

#endif /* _SMBFS_H */
