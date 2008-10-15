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

#define FILTER_DIRS(m)  S_ISDIR(m)
#define FILTER_FILES(m) S_ISREG(m)

#define MAX_RECUSIVE_DEPTH	127

/* we need this mask to detect changes in subdirs */
#define SYS_MASK IN_MOVED_FROM|IN_MOVED_TO|IN_CREATE|IN_DELETE

struct directory_info {
	char pathname[PATH_MAX];	/* the pathname being listened */
	int mask;					/* CLOSE_WRITE, MOVED_TO, MOVED_FROM or DELETE */
	char exec_cmd[LINE_MAX];	/* shell command to spawn when triggered */
	regex_t regex;				/* regular expression used to filter {file,dir} names */
	char regex_rule[LINE_MAX];	/* the rule in text form */
	int recursive;				/* recursive flag */

	int wd;						/* this pathname's watch file descriptor */
	int filter;					/* while reading the directory, only look at this kind of entries */
	int uses_entry_variable;	/* tells if exec_cmd uses the $ENTRY variable */

	struct directory_info *root;
	struct directory_info *next;
};

struct thread_info {
	struct directory_info *di;		/* the struct directory_info */
	char offending_name[PATH_MAX];	/* the file/directory entry we're dealing with */
};

struct directory_info * monitor_directory(int i, struct directory_info *di);

#endif /* LISTENER_H */
