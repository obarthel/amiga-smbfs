/*
 * http://codereview.stackexchange.com/questions/63493/simple-key-value-store-in-c-take-2
 * CC BY-SA
 *
 * Parts copyright (c) 2015-2021 Tygre <tygre@chingu.asia>
 * These parts are under the same license CC BY-SA as the original source code.
 */



/* Includes */

#include "kvs.h"

#include <stdlib.h> // For realloc()...
#include <string.h> // For memmove()...



/* Constants and declarations */

struct KVSpair {
	const KVSkey   *key;
		  KVSvalue *value;
};

struct KVSstore {
	KVSpair          *pairs;
	const KVScompare *compare;
	size_t            length;
	size_t             space;
};

	   KVSstore *kvs_create(const KVScompare *);
	   void      kvs_destroy(const KVSstore *);
	   void      kvs_put(const KVSstore *, const KVSkey *, const KVSvalue *);
	   KVSkey   *kvs_get_key(const KVSstore *, const size_t);
	   KVSvalue *kvs_get_value(const KVSstore *, const KVSkey *);
	   void      kvs_remove(const KVSstore *, const KVSkey *);
	   size_t    kvs_length(const KVSstore *);
	   int       kvs_compare_pointers(const KVSkey *, const KVSkey *);
	   int       kvs_compare_unsigned_longs(const KVSkey *, const KVSkey *);
	   int       kvs_compare_strings(const KVSkey *, const KVSkey *);
static KVSpair  *kvs_search(const KVSstore *, const KVSkey *, const int);
static KVSpair  *kvs_get_pair(const KVSstore *, const KVSkey *);
static void      kvs_resize_pairs(const KVSstore *, const size_t);
static void      _kvs_resize_pairs(const KVSstore *, const size_t);
static size_t    kvs_get_pair_index(const KVSstore *, const KVSpair *);
static size_t    kvs_get_bytes_from_pair(const KVSstore *, const KVSpair *);
static void      kvs_create_pair(const KVSstore *, const KVSkey *, const KVSvalue *);
static void      kvs_remove_pair(const KVSstore *, const KVSpair *);

static const size_t _kvs_pair_size  = sizeof(KVSpair);
static const size_t _kvs_store_size = sizeof(KVSstore);



/* Definitions */

KVSstore *kvs_create(
	      const KVScompare *compare)
{
	KVSstore *store = malloc(_kvs_store_size);
	if(store == NULL)
	{
		// TODO: Add SMBFS-compliant error reporting
		// log_print_fatal_error( GetString( MSG_KVS_KVSCREATECOULDNOTALLOCATEMEMORY ) );
		return NULL;
	}
	
	store->pairs = NULL;
	store->length = 0;
	store->space = 0;
	if(compare)
	{
		store->compare = compare;
	}
	else
	{
		store->compare = kvs_compare_pointers;
	}
	kvs_resize_pairs(store, 0);
	return store;
}

void kvs_destroy(
	 const KVSstore *store)
{
	KVSkey   *key    = NULL;
	KVSvalue *value  = NULL;
	int       length = 0;
	
	if(!store)
	{
		return;
	}
	if(store->pairs)
	{
		length = kvs_length(store);
		while(length > 0)
		{
			length--;

			key   = kvs_get_key  (store, length);
			value = kvs_get_value(store, key);

			// printf("ppp %p %p\n", key, value);
			// printf("### %s <-> %s\n",  (char *)key,     (char *)value);
			// printf("@@@ %lu <-> %s\n", *((ULONG *)key), (char *)value);

			free((void *)key);
			free((void *)value);
		}
		free((void *)store->pairs);
	}
	free((void *)store);
}

void kvs_put(
	 const KVSstore *store,
	 const KVSkey   *key,
	 const void     *value)
{
	KVSpair *pair = kvs_get_pair(store, key);
	if(pair)
	{
		if(value)
		{
			free((void *)pair->key);
			free((void *)pair->value);
			
			pair->key   = (void *)key;
			pair->value = (void *)value;
		}
		else
		{
			kvs_remove_pair(store, pair);
		}
	}
	else if(value)
	{
		kvs_create_pair(store, key, value);
	}
}

KVSkey *kvs_get_key(
	const KVSstore *store,
	const size_t    index)
{
	if((!store) || (index >= store->length))
	{
		return NULL;
	}
	return (store->pairs + index)->key;
}

KVSvalue *kvs_get_value(
	const KVSstore *store,
	const KVSkey   *key)
{
	KVSpair *pair = kvs_get_pair(store, key);
	return pair ? pair->value : NULL;
}

void kvs_remove(
	const KVSstore *store,
	const KVSkey   *key)
{
	kvs_put(store, key, NULL);
}

size_t kvs_length(
	const KVSstore *store)
{
	if(!store)
	{
		return 0;
	}
	return store->length;
}

int kvs_compare_pointers(
	const KVSkey *a,
	const KVSkey *b)
{
	return (char *)a - (char *)b;
}

int kvs_compare_unsigned_longs(
	const KVSkey *a,
	const KVSkey *b)
{
	ULONG x = *((ULONG *)a);
	ULONG y = *((ULONG *)b);

	return (int)(x - y);
}

int kvs_compare_strings(
	const KVSkey *a,
	const KVSkey *b)
{
	char *x = (char *)a;
	char *y = (char *)b;

	return strcmp(x, y);
}

static KVSpair *kvs_search(
	const KVSstore *store,
	const KVSkey   *key,
	const int       exact)
{
	size_t      lbound  = 0;
	size_t      rbound  = store->length;
	size_t      index   = 0;
	KVSpair    *element = NULL;
	KVSpair    *pairs   = store->pairs;
	int         result  = 0;
	KVScompare *compare = (KVScompare *)store->compare;
	// Cannot compile with VBCC v0.8f or v0.9g because of "internal error 0 in line 5307 of file machines/m68k/machine.c":
	// 	const KVScompare *compare = store->compare;

	while(lbound < rbound)
	{
		index   = lbound + ((rbound - lbound) >> 1);
		element = pairs + index;
		result  = compare(key, element->key);
		if(result < 0)
		{
			rbound = index;
		}
		else if(result > 0)
		{
			lbound = index + 1;
		}
		else
		{
			return element;
		}
	}
	return exact ? NULL : pairs + lbound;
}

static KVSpair *kvs_get_pair(
	const KVSstore *store,
	const KVSkey   *key)
{
	if((!store) || (!store->pairs))
	{
		return NULL;
	}
	return kvs_search(store, key, 1);
}

static void kvs_resize_pairs(
	const KVSstore *store,
	const size_t    amount)
{
	_kvs_resize_pairs((KVSstore *)store, amount);
}

static void _kvs_resize_pairs(
	const KVSstore *store,
	const size_t    amount)
{
	if(!store)
	{
		return;
	}
	((KVSstore *)store)->length += amount;
	if(store->space > store->length * _kvs_pair_size)
	{
		return;
	}
	((KVSstore *)store)->space += _kvs_pair_size;
	((KVSstore *)store)->pairs  = realloc(store->pairs, store->space);

	if(store->pairs == NULL)
	{
		// TODO: Add SMBFS-compliant error reporting
		// log_print_fatal_error( GetString( MSG_KVS_KVSRESIZEPAIRSCOULDNOTALLOCATEMEMORY ) );
	}
}

static size_t kvs_get_pair_index(
	const KVSstore *store,
	const KVSpair  *pair)
{
	if((!store) || (!pair))
	{
		return -1;
	}
	return (size_t)(pair - store->pairs);
}

static size_t kvs_get_bytes_from_pair(
	const KVSstore *store,
	const KVSpair  *pair)
{
	size_t pair_index;

	if((!store) || (!pair))
	{
		return 0;
	}
	pair_index = kvs_get_pair_index(store, pair);
	return (store->length - pair_index) * _kvs_pair_size;
}

static void kvs_create_pair(
	const KVSstore *store,
	const KVSkey   *key,
	const KVSvalue *value)
{
	KVSpair *pair;

	if(!store)
	{
		return;
	}
	pair = kvs_search(store, key, 0);
	if(pair < store->pairs + store->length)
	{
		size_t bytes = kvs_get_bytes_from_pair(store, pair);
		memmove(pair + 1, pair, bytes);
	}
	pair->key   = (void *)key;
	pair->value = (void *)value;
	kvs_resize_pairs(store, +1);
}

static void kvs_remove_pair(
	const KVSstore *store,
	const KVSpair  *pair)
{
	if((!store) || (!pair))
	{
		return;
	}
	free((void *)pair->key);
	free((void *)pair->value);
	memmove((void *)pair, (void *)(pair + 1), kvs_get_bytes_from_pair(store, pair + 1));
	kvs_resize_pairs(store, -1);
}

