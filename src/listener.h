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
#ifndef LISTENER_H
#define LISTENER_H 1

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <dirent.h>
#include <limits.h>
#include <regex.h>
#include <ftw.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#define _GNU_SOURCE
#include <getopt.h>
#include "inotify.h"
#include "inotify-syscalls.h"

#ifndef SYSCONFDIR
#define SYSCONFDIR      "/System/Settings"
#endif

#define LISTENER_RULES  SYSCONFDIR"/listener.conf"
#define EMPTY_MASK      0

#define FILTER_DIRS(m)     S_ISDIR(m)
#define FILTER_FILES(m)    S_ISREG(m)
#define FILTER_SYMLINKS(m) S_ISLNK(m)

#define MAX_RECUSIVE_DEPTH	127

/* we need this mask to detect changes in subdirs */
#define SYS_MASK IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE|IN_DELETE_SELF|IN_MOVE_SELF

typedef struct watch_entry {
	char target[PATH_MAX];		/* the pathname being listened */
	int mask;					/* CLOSE_WRITE, MOVED_TO, MOVED_FROM or DELETE */
	char spawn[LINE_MAX];		/* shell command to spawn when triggered */
	regex_t regex;				/* regular expression used to filter {file,dir} names */
	char regex_rule[LINE_MAX];	/* the rule in text form */
	int depth;					/* depth level */

	int wd;						/* @target watch file descriptor */
	int lookat;					/* while reading the directory, only look at this kind of entries */
	int uses_entry_variable;	/* tells if @spawn uses the $ENTRY variable */

	struct watch_entry *root;
	struct watch_entry *next;
} watch_t;

struct thread_info {
	struct watch_entry *watch;		/* the struct watch_entry */
	char *event_msg;                /* event message to be shown in the console */
	char offending_name[PATH_MAX];	/* the file/directory entry we're dealing with */
};

/* function prototypes */
watch_t *monitor_directory(int i, watch_t *watch);

#endif /* LISTENER_H */
