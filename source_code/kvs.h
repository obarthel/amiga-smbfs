/*
 * http://codereview.stackexchange.com/questions/63493/simple-key-value-store-in-c-take-2
 * CC BY-SA
 *
 * Changes by Tygre as part of AmiModRadio.
 * tygre@chingu.asia
 */

#ifndef KVS_H
#define KVS_H 1

#include <stddef.h>

typedef struct KVSstore KVSstore;
typedef struct KVSpair  KVSpair;
typedef void   KVSkey;
typedef void   KVSvalue;
typedef int    KVScompare(const KVSkey *a, const KVSkey *b);

KVSstore *kvs_create(
		  const KVScompare *compare);

void      kvs_destroy(
		  const KVSstore   *store);

void      kvs_put(
		  const KVSstore   *store,
		  const KVSkey     *key,
		  const KVSvalue   *value);

KVSkey   *kvs_get_key(
		  const KVSstore   *store,
		  const size_t      index);

KVSvalue *kvs_get_value(
		  const KVSstore   *store,
		  const KVSkey     *key);

void      kvs_remove(
		  const KVSstore   *store,
		  const KVSkey     *key);

size_t    kvs_length(
		  const KVSstore   *store);

int       kvs_compare_pointers(
		  const KVSkey     *a,
		  const KVSkey     *b);

int       kvs_compare_unsigned_longs(
		  const KVSkey     *a,
		  const KVSkey     *b);

int       kvs_compare_strings(
		  const KVSkey     *a,
		  const KVSkey     *b);
#endif
