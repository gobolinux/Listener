/*
 * Listener - Listens for specific directories events and take actions
 * based on rules specified by the user.
 *
 * Copyright (c) 2005-2017 Lucas C. Villa Real <lucasvr@gobolinux.org>
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
#ifndef __HASHTABLE_H
#define __HASHTABLE_H

#include <openssl/lhash.h>

_LHASH  *hashtable_create(watch_t *watch_list);
void     hashtable_destroy(_LHASH *hash);
watch_t *hashtable_get(_LHASH *hash, int key);

#endif /* __HASHTABLE_H */
