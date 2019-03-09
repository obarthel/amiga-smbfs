/*
 * :ts=4
 *
 * SMB file system wrapper for AmigaOS, using the AmiTCP V3 API
 *
 * Copyright (C) 2000-2019 by Olaf 'Olsen' Barthel <obarthel -at- gmx -dot- net>
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

#ifndef _SPLAY_H
#define _SPLAY_H

/****************************************************************************/

/* This enables the use of splay trees for faster validation of
 * file and lock pointers, and for faster lookup of file, directory
 * and path names.
 */
#define USE_SPLAY_TREE

/****************************************************************************/

#if defined(USE_SPLAY_TREE)

/****************************************************************************/

typedef void * splay_key_t;

/****************************************************************************/

typedef int (*splay_key_compare_t)(const splay_key_t a, const splay_key_t b);

/****************************************************************************/

struct splay_node
{
	struct splay_node *	sn_left;		/* Left child */
	struct splay_node *	sn_right;		/* Right child */
	splay_key_t			sn_key;			/* Unique identifier */
	struct splay_node *	sn_next;		/* For duplicates */
	APTR				sn_userdata;	/* For embedding */
};

struct splay_tree
{
	struct splay_node *	st_root;
	splay_key_compare_t	st_compare;
	BOOL				st_allow_duplicates;
};

/****************************************************************************/

BOOL splay_tree_add(struct splay_tree *tree, struct splay_node *new_node);
struct splay_node *splay_tree_remove(struct splay_tree *tree, struct splay_node * this_node, const splay_key_t key);
struct splay_node *splay_tree_find(struct splay_tree *tree, const splay_key_t key);
void splay_tree_init(struct splay_tree *tree, splay_key_compare_t compare);

/****************************************************************************/

#endif /* USE_SPLAY_TREE */

/****************************************************************************/

#endif /* _SPLAY_H */
