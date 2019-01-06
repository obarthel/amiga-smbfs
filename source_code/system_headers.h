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

#ifndef _SYSTEM_HEADERS_H
#define _SYSTEM_HEADERS_H 1

/*****************************************************************************/

#define __USE_INLINE__
#define __NOGLOBALIFACE__
#define __NOLIBBASE__

/****************************************************************************/

#if defined(__SASC)
#define USE_BUILTIN_MATH
#endif /* __SASC */

/*****************************************************************************/

#define NULL ((APTR)0L)
#include <exec/types.h>

/*****************************************************************************/

/* The <smb/smb.h> header file declares this, and it may be redefined
 * in the TCP/IP stack header files. We try to avoid trouble by moving
 * the type declaration out of the way...
 */
#define byte IGNORE_THIS

/*****************************************************************************/

#include <workbench/workbench.h>
#include <workbench/startup.h>

#include <dos/dosextens.h>
#include <dos/dosasl.h>
#include <dos/dostags.h>
#include <dos/filehandler.h>
#include <dos/rdargs.h>
#include <dos/exall.h>

#if defined(__amigaos4__)
#include <dos/obsolete.h>
#endif /* __amigaos4__ */

#include <exec/memory.h>

#include <devices/timer.h>
#include <devices/inputevent.h>
#include <devices/input.h>

#include <libraries/locale.h>

#include <utility/date.h>
#include <utility/tagitem.h>

/*****************************************************************************/

#include <clib/alib_protos.h>

/*****************************************************************************/

/* A quick workaround for the timeval/timerequest->TimeVal/TimeRequest
   change in the recent OS4 header files. */
#if defined(__NEW_TIMEVAL_DEFINITION_USED__)

#define timeval		TimeVal
#define tv_secs		Seconds
#define tv_micro	Microseconds

#define timerequest	TimeRequest
#define tr_node		Request
#define tr_time		Time

#endif /* __NEW_TIMEVAL_DEFINITION_USED__ */

/*****************************************************************************/

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/intuition.h>
#include <proto/bsdsocket.h>
#include <proto/utility.h>
#include <proto/locale.h>
#include <proto/timer.h>
#include <proto/icon.h>

/*
#include <clib/exec_protos.h>
#include <clib/dos_protos.h>
#include <clib/intuition_protos.h>
#include <clib/bsdsocket_protos.h>
#include <clib/utility_protos.h>
#include <clib/locale_protos.h>
#include <clib/timer_protos.h>
#include <clib/icon_protos.h>
*/

/*****************************************************************************/

/* This is for backwards compatibility only. */
#if defined(__amigaos4__)
#define fib_EntryType fib_Obsolete
#endif /* __amigaos4__ */

/*****************************************************************************/

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
/*#include <sys/param.h>*/
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <net/if.h>
#include <unistd.h>
#include <netdb.h>

/*****************************************************************************/

#undef byte

/*****************************************************************************/

/* This is for use with the profiling support of the SAS/C compiler and
 * its runtime library. The macros defined in the header file are replaced
 * by no-ops for other compilers.
 */
#if defined(__SASC) && defined(_PROFILE)

#include <sprof.h>

#if _PROFILE

/* The profiling disable/enable calls need to nest, which is
 * why we use our own local counter and some corresponding
 * macros instead of the SAS/C-supplied versions. See the
 * <sprof.h> header file how they are supposed to work.
 */
extern int profile_nest_count;

#undef PROFILE_ON
#undef PROFILE_OFF

extern void kprintf(const char *fmt, ...);

#define PROFILE_OFF() { if(profile_nest_count++ == 0) _PROLOG(0L); }
#define PROFILE_ON() { if(--profile_nest_count == 0) _EPILOG(0L); }
#endif /* _PROFILE */

#else

#define PROFILE_OFF() {}
#define PROFILE_ON() {}

#define PROFILE_PUSH(x) {}
#define PROFILE_POP(x) {}

#endif /* __SASC */

/*****************************************************************************/

#endif /* _SYSTEM_HEADERS_H */
