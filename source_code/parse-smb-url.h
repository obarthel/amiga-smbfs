/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2019 by Olaf 'Olsen' Barthel <obarthel -at- gmx -dot- net>
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

#ifndef _PARSE_SMB_URL_H
#define _PARSE_SMB_URL_H

/****************************************************************************/

#include <stddef.h>

/****************************************************************************/

/* SMB URI parameters, as processed and produced by parse_smb_url_args(). */
struct smb_url_args
{
	/* Each string pointer is either a NULL pointer (not provided by the
	 * URI text), or it points to a NUL-terminated string.
	 */
	char * domain;
	char * username;
	char * password;
	char * server;
	char * port;
	char * share;
	char * path;
};

/****************************************************************************/

int could_be_smb_url(const char * arg);
struct smb_url_args * parse_smb_url_args(const char * arg);
void free_smb_url_args(struct smb_url_args *args);

/****************************************************************************/

#endif /* _PARSE_SMB_URL_H */
