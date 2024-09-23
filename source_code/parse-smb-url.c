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

#include "smbfs.h"
#include "parse-smb-url.h"

/****************************************************************************/

#include <string.h>

/****************************************************************************/

/* Free all the memory allocated by parse_smb_url_args(). */
void
free_smb_url_args(struct smb_url_args *args)
{
	if(args != NULL)
	{
		if(args->domain != NULL)
			free(args->domain);

		if(args->username != NULL)
			free(args->username);

		if(args->password != NULL)
			free(args->password);

		if(args->server != NULL)
			free(args->server);

		if(args->port != NULL)
			free(args->port);

		if(args->share != NULL)
			free(args->share);

		if(args->path != NULL)
			free(args->path);
	}
}

/****************************************************************************/

/* Allocate memory for the SMB url parser and initialize its
 * contents to be empty.
 */
static struct smb_url_args *
allocate_smb_url_args(void)
{
	struct smb_url_args * args;

	args = calloc(1, sizeof(*args));

	return(args);
}

/****************************************************************************/

/* Allocate enough memory to hold a NUL-terminated copy of the substring
 * whose start/end position is provided, then copy its contents. Returns
 * NULL on failure. Note that the start/end positions are expected to be
 * start <= end.
 */
static char *
copy_substring(const char * arg, size_t start, size_t end)
{
	char * buffer;
	size_t len;

	ASSERT( arg != NULL );
	ASSERT( start <= end );

	len = end - start;

	buffer = malloc(len+1);
	if(buffer != NULL)
	{
		memcpy(buffer, &arg[start], len);
		buffer[len] = '\0';
	}

	return(buffer);
}

/****************************************************************************/

/* Quick check if a character can be part of a hexadecimal digit string. */
static int
is_hex(int c)
{
	return(('0' <= c && c <= '9') ||
	       ('a' <= c && c <= 'f') ||
	       ('A' <= c && c <= 'F'));
}

/* Convert a character which is known to be valid as part of a hexadecimal
 * string into its numeric representation.
 */
static int
hex_to_dec(int c)
{
	int result;

	if('0' <= c && c <= '9')
		result = c - '0';
	else
		result = 9 + (c & 7);

	return(result);
}

/****************************************************************************/

/* Scan a string for URI escape sequences, replacing them with the
 * decoded octet value in place. Replacing the encoded sequence will
 * cause the string to become shorter. The resulting string will
 * be NUL-terminated.
 */
static void
replace_escape_sequences(char * s, size_t len)
{
	size_t i, j, n;
	int c;

	for(i = j = n = 0 ; i < len ; i++, j++)
	{
		c = s[i];

		if(c == '%' && i+2 < len && is_hex(s[i+1]) && is_hex(s[i+2]))
		{
			c = 16 * hex_to_dec(s[i+1]) + hex_to_dec(s[i+2]);

			i += 2;

			s[j] = c;
		}
		else if (i != j)
		{
			s[j] = c;
		}
	}

	s[j] = '\0';
}

/****************************************************************************/

/* Check if the string could be an SMB file sharing URI, which
 * means that it begins with "smb://".
 */
int
could_be_smb_url(const char * arg)
{
	int result;

	result = (arg != NULL && strncasecmp(arg, "smb://", 6) == 0);

	return(result);
}

/****************************************************************************/

/* Attempt to process an SMB file sharing URI, as described in the
 * January 8, 2007 IETF draft titled "SMB File Sharing URI Scheme",
 * as submitted by Christopher R. Hertel and the Samba Team.
 *
 * This implementation does not use the parameters which the draft
 * describes since they are not supported by the Amiga smbfs program.
 *
 * This function will return NULL in case of failure. Processing and
 * validating the individual URI components is the job of the caller,
 * we only try to parse the URI string here. Note that the parser is
 * not particularly sophisticated...
 */
struct smb_url_args *
parse_smb_url_args(const char * arg)
{
	size_t len = strlen(arg);

	size_t domain_start = 0;
	size_t domain_end = 0;
	size_t username_start = 0;
	size_t username_end = 0;
	size_t password_start = 0;
	size_t password_end = 0;
	size_t server_start = 0;
	size_t server_end = 0;
	size_t port_start = 0;
	size_t port_end = 0;
	size_t share_start = 0;
	size_t share_end = 0;
	size_t path_start = 0;
	size_t path_end = 0;
	size_t i;

	struct smb_url_args * result = NULL;
	struct smb_url_args * smb_url_args = NULL;

	ENTER();

	/* This should be an SMB url to begin with. */
	if(len <= 6 || !could_be_smb_url(arg))
	{
		SHOWMSG("not a valid SMB url");
		goto out;
	}

	/* Skip the "smb://" part. */
	arg += 6;
	len -= 6;

	smb_url_args = allocate_smb_url_args();
	if(smb_url_args == NULL)
		goto out;

	/* Try to find the optional domain name, user name
	 * and password in the URL. We look for the '@' character
	 * which separates this optional part from the
	 * server name.
	 */
	for(i = 0 ; i < len ; i++)
	{
		if(arg[i] == '@')
		{
			size_t at = i;
			size_t j;

			/* Could there be a domain name in front
			 * of the user name?
			 */
			for(j = 0 ; j < at ; j++)
			{
				if(arg[j] == ';')
				{
					domain_end = j;

					username_start = j+1;
					break;
				}
			}

			/* Try to obtain the user name and the
			 * optional password.
			 */
			for(j = username_start ; j <= at ; j++)
			{
				if(j == at || arg[j] == ':')
				{
					username_end = j;

					/* The password follows the ':'
					 * character, if there is one.
					 */
					if(j < at)
					{
						password_start = j+1;
						password_end = at;
					}

					break;
				}
			}

			/* The server name should follow the
			 * '@' character.
			 */
			server_start = at+1;

			break;
		}
	}

	/* Try to find the server name, which may be followed
	 * by a port number/service name, the share name
	 * or the parameter list.
	 */
	for(i = server_start ; i <= len ; i++)
	{
		if(i == len || arg[i] == '/' || arg[i] == ':')
		{
			server_end = i;

			if(i < len)
			{
				/* The port number/service name follow the
				 * ':' character.
				 */
				if(arg[i] == ':')
				{
					size_t j;

					port_start = i+1;

					/* Figure out how long the port number/service
					 * name text is, and pick up the start of the
					 * share name or the parameter list.
					 */
					for(j = port_start ; j <= len ; j++)
					{
						if(j == len || arg[j] == '/' || arg[j] == '?')
						{
							port_end = j;

							/* Did we find the share name? */
							if(j < len && arg[j] == '/')
								share_start = j+1;

							break;
						}
					}
				}
				/* We'll look for the share name instead.
				 * Of course, we could look for the parameter
				 * list, but the SMB URI is none too useful
				 * without the share name, so we prefer that
				 * instead.
				 */
				else
				{
					share_start = i+1;
				}
			}

			break;
		}
	}

	/* Try to find the share name, and pick up the
	 * path name or the parameter list which may
	 * follow it.
	 */
	if(share_start > 0)
	{
		for(i = share_start ; i <= len ; i++)
		{
			if(i == len || arg[i] == '/' || arg[i] == '?')
			{
				share_end = i;

				if(i < len)
				{
					/* Pick up the path name? */
					if(arg[i] == '/')
						path_start = i+1;
				}

				break;
			}
		}
	}

	/* Try to pick up the path name. */
	if(path_start > 0)
	{
		for(i = path_start ; i <= len ; i++)
		{
			if(i == len || arg[i] == '?')
			{
				path_end = i;
				break;
			}
		}
	}

	if(domain_start < domain_end)
	{
		smb_url_args->domain = copy_substring(arg, domain_start, domain_end);
		if(smb_url_args->domain == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->domain, domain_end - domain_start);

		D(("domain: '%s'", smb_url_args->domain));
	}
	else
	{
		SHOWMSG("no domain name provided");
	}

	if(username_start < username_end)
	{
		smb_url_args->username = copy_substring(arg, username_start, username_end);
		if(smb_url_args->username == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->username, username_end - username_start);

		D(("username: '%s'", smb_url_args->username));
	}
	else
	{
		SHOWMSG("no user name provided");
	}

	if(password_start < password_end)
	{
		smb_url_args->password = copy_substring(arg, password_start, password_end);
		if(smb_url_args->password == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->password, password_end - password_start);

		D(("password: ..."));
	}
	else
	{
		SHOWMSG("no password provided");
	}

	if(server_start < server_end)
	{
		smb_url_args->server = copy_substring(arg, server_start, server_end);
		if(smb_url_args->server == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->server, server_end - server_start);

		D(("server: '%s'", smb_url_args->server));
	}
	else
	{
		SHOWMSG("no server name provided");
	}

	if(port_start < port_end)
	{
		smb_url_args->port = copy_substring(arg, port_start, port_end);
		if(smb_url_args->port == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->port, port_end - port_start);

		D(("port: '%s'", smb_url_args->port));
	}
	else
	{
		SHOWMSG("no port number/service name provided");
	}

	if(share_start < share_end)
	{
		smb_url_args->share = copy_substring(arg, share_start, share_end);
		if(smb_url_args->share == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->share, share_end - share_start);

		D(("share: '%s'", smb_url_args->share));
	}
	else
	{
		SHOWMSG("no share name provided");
	}

	if(path_start < path_end)
	{
		smb_url_args->path = copy_substring(arg, path_start, path_end);
		if(smb_url_args->path == NULL)
		{
			SHOWMSG("not enough memory");
			goto out;
		}

		replace_escape_sequences(smb_url_args->path, path_end - path_start);

		D(("path: '%s'", smb_url_args->path));
	}
	else
	{
		SHOWMSG("no path name provided");
	}

	result = smb_url_args;
	smb_url_args = NULL;

 out:

	if(smb_url_args != NULL)
		free_smb_url_args(smb_url_args);

	RETURN(result);
	return(result);
}
