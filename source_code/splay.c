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

#include "smbfs.h"

/****************************************************************************/

#ifdef USE_SPLAY_TREE

/****************************************************************************/

/*
 * This implementation was adapted from Daniel Sleator's March 1992
 * top-down splaying example code.
 */

/****************************************************************************/

/* Simple top down splay, not requiring the key to be in the tree. */
static INLINE struct splay_node *
splay(splay_key_compare_t compare, struct splay_node * t, const splay_key_t key)
{
	struct splay_node N, *l, *r, *y;
	int d;

	memset(&N, 0, sizeof(N));

	l = r = &N;

	while((d = (*compare)(key, t->sn_key)) != 0)
	{
		if(d < 0)
		{
			if(t->sn_left == NULL)
				break;

			if((*compare)(key, t->sn_left->sn_key) < 0)
			{
				/* rotate right */
				y = t->sn_left;
				t->sn_left = y->sn_right;
				y->sn_right = t;
				t = y;

				if(t->sn_left == NULL)
					break;
			}

			/* link right */
			r->sn_left = t;
			r = t;
			t = t->sn_left;
		}
		else
		{
			if(t->sn_right == NULL)
				break;

			if((*compare)(key, t->sn_right->sn_key) > 0)
			{
				/* rotate left */
				y = t->sn_right;
				t->sn_right = y->sn_left;
				y->sn_left = t;
				t = y;

				if(t->sn_right == NULL)
					break;
			}

			/* link left */
			l->sn_right = t;
			l = t;
			t = t->sn_right;
		}
	}

	/* assemble */
	l->sn_right	= t->sn_left;
	r->sn_left	= t->sn_right;
	t->sn_left	= N.sn_right;
	t->sn_right	= N.sn_left;

	return(t);
}

/****************************************************************************/

/* Try to insert a node into the splay tree. Returns TRUE for success and
 * FALSE otherwise. FALSE indicates that a duplicate key was to be added
 * and could not be stored.
 */
BOOL
splay_tree_add(struct splay_tree * tree, struct splay_node * new_node)
{
	splay_key_compare_t compare;
	BOOL success = TRUE;

	ASSERT(tree != NULL && new_node != NULL);

	compare = tree->st_compare;

	if(tree->st_root != NULL)
	{
		struct splay_node * t;
		int d;

		t = splay(compare, tree->st_root, new_node->sn_key);

		d = (*compare)(new_node->sn_key, t->sn_key);

		if (d < 0)
		{
			new_node->sn_left	= t->sn_left;
			new_node->sn_right	= t;

			t->sn_left = NULL;
		}
		else if (d > 0)
		{
			new_node->sn_right	= t->sn_right;
			new_node->sn_left	= t;

			t->sn_right = NULL;
		}
		else
		{
			/* Can we add the duplicate to the list? */
			if(tree->st_allow_duplicates)
			{
				new_node->sn_next = t->sn_next;
				t->sn_next = new_node;
			}
			else
			{
				/* We do not allow duplicates in the tree. */
				success = FALSE;
			}

			/* Splaying the tree changed the root, which we
			 * will have to update.
			 */
			new_node = t;
		}
	}
	else
	{
		new_node->sn_left = new_node->sn_right = NULL;
	}

	tree->st_root = new_node;

	return(success);
}

/****************************************************************************/

/* Removes a node from the tree if it's there. Return a pointer to the
 * node or NULL if it could not be removed.
 */
struct splay_node *
splay_tree_remove(
	struct splay_tree *	tree,
	struct splay_node *	this_node,
	const splay_key_t	key)
{
	struct splay_node * result = NULL;

	ASSERT(tree != NULL);

	if(tree->st_root != NULL)
	{
		splay_key_compare_t compare = tree->st_compare;
		struct splay_node * t;

		t = splay(compare, tree->st_root, key);

		if((*compare)(t->sn_key, key) == 0)
		{
			struct splay_node * x;

			/* Are there duplicate keys attached to this node? */
			if(t->sn_next != NULL)
			{
				/* Find and remove a specific node? */
				if(this_node != NULL)
				{
					/* Remove the root? */
					if(this_node == t)
					{
						/* We return the root and install a node
						 * from the duplicate list in its place.
						 */
						result = t;

						/* The next node will do. */
						t = t->sn_next;

						/* Install a new root, but keep the linkage
						 * of the old root.
						 */
						t->sn_left = this_node->sn_left;
						t->sn_right = this_node->sn_right;
					}
					/* Remove one of the duplicates, keeping the current root. */
					else
					{
						struct splay_node * p;
						struct splay_node * n;

						/* We still have to find the duplicate which we
						 * intend to remove.
						 */
						result = NULL;

						/* Try to find the node to be removed among the duplicates,
						 * remove it from the list and return it.
						 */
						for(p = t, n = t->sn_next ; n != NULL ; p = n, n = n->sn_next)
						{
							if(this_node == n)
							{
								/* Remove this node from the list of duplicates. */
								p->sn_next = this_node->sn_next;

								/* Return this specific duplicate. */
								result = this_node;

								break;
							}
						}
					}
				}
				/* No, any node will do. */
				else
				{
					/* Return a duplicate, and remove it from the list. */
					result = t->sn_next;

					t->sn_next = result->sn_next;
				}
			}
			/* No duplicates expected; we found what we came for. */
			else
			{
				result = t;

				if(t->sn_left == NULL)
				{
					x = t->sn_right;
				}
				else
				{
					x = splay(compare, t->sn_left, key);

					x->sn_right = t->sn_right;
				}

				t = x;
			}
		}

		tree->st_root = t;
	}

	return(result);
}

/****************************************************************************/

/* Find a key in the tree, then splay the tree when the matching node is found.
 * Returns a pointer to the node found or NULL if none matches.
 *
 * If duplicates are permitted, the splay node returned can contain more
 * than one matching entry in the splay_node->sn_next list.
 */
struct splay_node *
splay_tree_find(struct splay_tree * tree, const splay_key_t key)
{
	splay_key_compare_t compare;
	struct splay_node * found = NULL;
	struct splay_node * t;
	int d;

	ASSERT(tree != NULL);

	compare = tree->st_compare;

	t = tree->st_root;

	while(t != NULL)
	{
		d = (*compare)(key, t->sn_key);
		if(d < 0)
		{
			/* Key is smaller than the current node; move left
			 * to a smaller node value.
			 */
			t = t->sn_left;
		}
		else if (d > 0)
		{
			/* Key is greater than the current node; move right
			 * to a greater node value.
			 */
			t = t->sn_right;
		}
		else
		{
			found = t;

			/* Found the key. Now splay the tree. */
			if(t != tree->st_root)
				tree->st_root = splay(compare, tree->st_root, key);

			break;
		}
	}

	return(found);
}

/****************************************************************************/

/* Initialize a splay tree to be empty. By default duplicate keys
 * are not allowed.
 */
void
splay_tree_init(struct splay_tree *tree, splay_key_compare_t compare)
{
	ASSERT( tree != NULL );

	tree->st_root				= NULL;
	tree->st_compare			= compare;
	tree->st_allow_duplicates	= FALSE;
}

/****************************************************************************/

#endif /* USE_SPLAY_TREE */
