/*
 * Listener - Listens for specific directories events and take actions 
 * based on rules specified by the user.
 *
 * Copyright (c) 2005-2017 Lucas C. Villa Real <lucasvr@gobolinux.org>
 * 
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "listener.h"
#include "hashtable.h"

static int hashtable_compare(const void *aa, const void *bb)
{
	const watch_t *a = (const watch_t *) aa;
	const watch_t *b = (const watch_t *) bb;
	return a->wd < b->wd ? -1 : a->wd == b->wd ? 0 : 1;
}

static unsigned long hashtable_compute_key(const void *entry)
{
	const watch_t *watch = (const watch_t *) entry;
	unsigned long hash = watch->wd;
	return hash;
}

watch_t *hashtable_get(_LHASH *hash, int key)
{
	watch_t obj = { .wd = key };
	watch_t *entry = (watch_t *) lh_retrieve(hash, &obj);
	return entry;
}

_LHASH *hashtable_create(watch_t *watch_list)
{
	_LHASH *hash = lh_new(hashtable_compute_key, hashtable_compare);
	for (watch_t *w = watch_list; w != NULL; w = w->next)
		lh_insert(hash, w);
	return hash;
}

void hashtable_destroy(_LHASH *hash)
{
	void hashtable_destroy_entry(void *entry) {
		lh_delete(hash, entry);
	}

	lh_doall(hash, hashtable_destroy_entry);
	lh_free(hash);
}
