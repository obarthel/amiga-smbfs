/*
 * $Id: smb_mount.h,v 1.1.1.1 2005/05/24 13:22:14 obarthel Exp $
 *
 * :ts=8
 *
 * smb_mount.h
 *
 * Copyright (C) 1995 by Paal-Kr. Engstad and Volker Lendecke
 * Modified for use with AmigaOS by Olaf Barthel <obarthel -at- gmx -dot- net>
 */

#ifndef _SMB_MOUNT_H
#define _SMB_MOUNT_H

#include <netinet/in.h>

struct smb_mount_data
{
  int fd;

  struct sockaddr_in addr;

  char workgroup_name[17];
  char server_name[17];
  char client_name[17];
  char service[64];

  char username[64];
  char password[64];

  int given_max_xmit;
};

#endif
