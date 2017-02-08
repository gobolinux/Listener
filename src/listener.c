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
#include "rules.h"

struct listener_ctx {
	watch_t *watch_list;
	_LHASH *watch_hash;
	int inotify_fd;
	int debug_mode;
};

static struct listener_ctx ctx;

#define debug_printf(fmt, args...)	if(ctx.debug_mode) printf(fmt, ##args)

void
suicide(int signum)
{
	/* Hashtable must be destroyed first */
	hashtable_destroy(ctx.watch_hash);

	for (watch_t *ptr=ctx.watch_list; ptr != NULL; ptr=ptr->next) {
		if (ptr->regex_rule[0])
			regfree(&ptr->regex);
	}
	free(ctx.watch_list);

	close(ctx.inotify_fd);
	exit(EXIT_SUCCESS);
}

void *
perform_action(void *thread_info)
{
	pid_t pid;
	char target[PATH_MAX];
	struct thread_info *info = (struct thread_info *) thread_info;
	watch_t *watch = info->watch;

	snprintf(target, sizeof(target), "%s/%s", watch->target, info->offending_name);

	pid = fork();
	if (pid == 0) {
		char **exec_array, *cmd = watch->spawn;
		char spawn[LINE_MAX] = { 0 };
		int len = strlen(cmd);
		int skipped = 0;

		while (2) {
			int skip_bytes = 0;
			char *token = get_token(cmd, &skip_bytes, watch->target, info);
			if (! token)
				break;

			cmd += skip_bytes;
			skipped += skip_bytes;

			strcat(spawn, token);
			strcat(spawn, " ");
			free(token);

			if (skipped >= len)
				break;
		}
		exec_array = (char **) malloc(4 * sizeof(char *));
		exec_array[0] = "/bin/sh";
		exec_array[1] = "-c";
		exec_array[2] = strdup(spawn);
		exec_array[3] = NULL;
		if (ctx.debug_mode) {
			int i;
			for (i = 0; exec_array[i] != NULL; ++i)
				printf("token: '%s'\n", exec_array[i]);
		}
		free(info->watch);
		free(info);
		execvp(exec_array[0], exec_array);

	} else if (pid > 0) {
		waitpid(pid, NULL, WUNTRACED);
	} else {
		perror("fork");
	}

	pthread_exit(NULL);
}

void
rebuild_tree(watch_t *start, watch_t *watch)
{
	watch_t *ptr, *prev;
	watch_t *root = watch->root; 

	/* free all entries from this directory tree */
	prev = NULL;
	for (ptr = start; ptr != NULL; ptr = ptr->next) {
		if(ptr == root) {
			prev = ptr;
			continue;
		}
			
		if (ptr->root == root) {
			prev->next = ptr->next;
			inotify_rm_watch(ctx.inotify_fd, ptr->wd);
			if (ptr->regex_rule[0])
				regfree(&ptr->regex);
			free(ptr);
			ptr = prev;
		} else {
			prev = ptr;
		}
	}
	
	monitor_directory(0, root);
}

void
select_on_inotify(void)
{
	int ret;
	fd_set read_fds;

	FD_ZERO(&read_fds);
	FD_SET(ctx.inotify_fd, &read_fds);

	ret = select(ctx.inotify_fd + 1, &read_fds, NULL, NULL, NULL);
	if (ret == -1)
		perror("select");
}

static inline void
mask_concat(char *buf, size_t size, const char *data)
{
	size_t offset = strlen(buf);
	if (offset == 0) {
		strncat(buf, data, size);
	} else {
		char *start = &buf[offset];
		snprintf(start, size-offset-1, " | %s", data);
	}
}

char *
mask_name(int mask)
{
	char buf[128] = { 0 };

	if (mask & IN_ACCESS)
		mask_concat(buf, sizeof(buf), "access");
	if (mask & IN_MODIFY)
		mask_concat(buf, sizeof(buf), "modify");
	if (mask & IN_ATTRIB)
		mask_concat(buf, sizeof(buf), "attrib");
	if (mask & IN_CLOSE_WRITE)
		mask_concat(buf, sizeof(buf), "close write");
	if (mask & IN_CLOSE_NOWRITE)
		mask_concat(buf, sizeof(buf), "close nowrite");
	if (mask & IN_OPEN)
		mask_concat(buf, sizeof(buf), "open");
	if (mask & IN_MOVED_FROM)
		mask_concat(buf, sizeof(buf), "moved from");
	if (mask & IN_MOVED_TO)
		mask_concat(buf, sizeof(buf), "moved to");
	if (mask & IN_CREATE)
		mask_concat(buf, sizeof(buf), "create");
	if (mask & IN_DELETE)
		mask_concat(buf, sizeof(buf), "delete");
	if (mask & IN_DELETE_SELF)
		mask_concat(buf, sizeof(buf), "delete self");
	if (mask & IN_MOVE_SELF)
		mask_concat(buf, sizeof(buf), "move self");
	if (! strlen(buf)) {
		char unknown[64];
		snprintf(unknown, sizeof(unknown)-1, "unknown (%#x)", mask);
		mask_concat(buf, sizeof(buf), unknown);
	}

	return strdup(buf);
}

void
handle_events(const struct inotify_event *ev)
{
	pthread_t tid;
	regmatch_t match;
	struct thread_info *info;
	struct stat status;
	char stat_target[PATH_MAX], offending_name[PATH_MAX];
	watch_t *watch = NULL;
	char *mask;
	int ret, need_rebuild_tree = 0;

	watch = hashtable_get(ctx.watch_hash, ev->wd);
	if (! watch) {
		/* Couldn't find watch descriptor, so this is not a valid event */
		return;
	}

	/*
	 * first, check against the watch mask, since a given entry can be
	 * watched twice or even more times
	 */
	if (! (watch->mask & ev->mask)) {
		if (ctx.debug_mode) {
			char *wa_mask = mask_name(watch->mask);
			char *ev_mask = mask_name(ev->mask);
			debug_printf("watch mask mismatch on %d: watch=%s, event=%s\n", watch->wd, wa_mask, ev_mask);
			free(wa_mask);
			free(ev_mask);
		}
		return;
	}

	if (! (ev->mask & (IN_DELETE_SELF|IN_MOVE_SELF))) {
		if (watch->regex_rule[0]) {
			/* verify against regex if we want to handle this event or not */
			memset(offending_name, 0, sizeof(offending_name));
			snprintf(offending_name, ev->len, "%s", ev->name);
			ret = regexec(&watch->regex, offending_name, 1, &match, 0);
			if (ret != 0) {
				debug_printf("event from watch %d, but path '%s' doesn't match regex\n", watch->wd, offending_name);
				return;
			}
		}

		/* filter the entry by its type (dir|file) */
		snprintf(stat_target, sizeof(stat_target), "%s/%s", watch->target, offending_name);
		ret = stat(stat_target, &status);
		if (ret < 0 && watch->uses_entry_variable && ! (watch->mask & IN_DELETE || watch->mask & IN_DELETE_SELF)) {
			fprintf(stderr, "stat %s: %s\n", stat_target, strerror(errno));
			return;
		}
		if (!(FILTER_DIRS(watch->lookat) && S_ISDIR(status.st_mode)) &&
				!(FILTER_FILES(watch->lookat) && S_ISREG(status.st_mode)) &&
				!(FILTER_SYMLINKS(watch->lookat) && S_ISLNK(status.st_mode)) &&
				ret == 0) {
			const char *fsobj = S_ISDIR(status.st_mode) ? "DIRS" :
				S_ISREG(status.st_mode) ? "FILES" : "SYMLINKS";
			debug_printf("watch %d doesn't want to process %s, skipping event\n", watch->wd, fsobj);
			return;
		}
	} else {
		strncpy(offending_name, watch->target, sizeof(offending_name)-1);
	}

	mask = mask_name(ev->mask);
	debug_printf("-> event on dir %s, watch %d\n", watch->target, watch->wd);
	debug_printf("-> filename:    %s\n", offending_name);
	debug_printf("-> event mask:  %#X (%s)\n\n", ev->mask, mask);
	free(mask);

	if (watch->depth && ((SYS_MASK) & ev->mask))
		need_rebuild_tree = 1;

	/* launch a thread to deal with the event */
	info = (struct thread_info *) malloc(sizeof(struct thread_info));
	info->watch = (watch_t *) malloc(sizeof(watch_t));
	memcpy(info->watch, watch, sizeof(watch_t));
	snprintf(info->offending_name, sizeof(info->offending_name), "%s", offending_name);
	pthread_create(&tid, NULL, perform_action, (void *) info);

	/* event handled, that's all! */

	if (need_rebuild_tree) {
		hashtable_destroy(ctx.watch_hash);
		rebuild_tree(ctx.watch_list, watch);
		ctx.watch_hash = hashtable_create(ctx.watch_list);
	}
}

void
listen_for_events(void)
{
	size_t n;
	char *ptr;
	char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *event = NULL;

	while (2) {
		select_on_inotify();
		n = read(ctx.inotify_fd, buf, sizeof(buf));
		if (n <= 0)
			break;

		for (ptr=buf; ptr<buf+n; ptr+=sizeof(struct inotify_event)+event->len) {
			event = (const struct inotify_event *) ptr;
			handle_events(event);
		}
	}
}

watch_t *
monitor_directory(int i, watch_t *watch)
{
	uint32_t mask, current_mask, my_root_mask;
	watch_t *ptr, *my_root;

	int walk_tree(const char *file, const struct stat *sb, int flag, struct FTW *li) {
		watch_t *w;

		if (flag != FTW_D) /* isn't a subdirectory */
			return 0;
		if (li->level > my_root->depth)
			return FTW_SKIP_SUBTREE;

		/*
		 * replicate the parent's spawn, uses_entry_variable, mask, lookat,
		 * regex and depth members
		 */
		w = (watch_t *) calloc(1, sizeof(watch_t));
		memcpy(w, my_root, sizeof(*w));

		/* only needs to differentiate on the target, regex and watch descriptor */
		snprintf(w->target, sizeof(w->target), "%s", file);
		if (strlen(w->regex_rule)) {
			regcomp(&w->regex, w->regex_rule, REG_EXTENDED);
		}
		w->wd = inotify_add_watch(ctx.inotify_fd, file, my_root_mask | SYS_MASK);
		if (w->wd < 0) {
			perror("inotify_add_watch");
			exit(1);
		}

		my_root->next = w;
		my_root = w;

		if (i) { debug_printf("[recursive] Monitoring %s on watch %d\n", w->target, w->wd); }
		return FTW_CONTINUE;
	}

	/* 
	 * Check for the existing entries if this directory is already being listened.
	 * If we have a match, then we must append a new mask instead of replacing the
	 * current one.
	 */
	for (current_mask=0, ptr=ctx.watch_list; ptr != NULL; ptr=ptr->next) {
		if (! strcmp(ptr->target, watch->target))
			current_mask |= ptr->mask;
	}

	mask = watch->mask | current_mask;
	watch->root = watch; //pointer to root diretory
	
	if (watch->depth) {
		my_root = watch;
		my_root_mask = mask;
		nftw(watch->target, walk_tree, 1024, FTW_ACTIONRETVAL);
		watch = my_root;
	} else {
		watch->wd = inotify_add_watch(ctx.inotify_fd, watch->target, mask);
		if (watch->wd < 0) {
			fprintf(stderr, "inotify_add_watch(%d, %s, %#x): %s\n", ctx.inotify_fd, watch->target, mask, strerror(errno));
			exit(1);
		}
		if (i) { debug_printf("Monitoring %s on watch %d\n", watch->target, watch->wd); }
	}
	return watch;
}

void
show_usage(char *program_name)
{
	fprintf(stderr, "Usage: %s [options]\n\nAvailable options are:\n"
			"  -c, --config FILE    Take config options from FILE\n"
			"  -d, --debug          Run in the foreground\n"
			"  -h, --help           This help\n", program_name);
}

void
close_standard_descriptors()
{
	int devnull_in = open("/dev/null", O_WRONLY);
	int devnull_out = open("/dev/null", O_RDONLY);
	dup2(devnull_in, STDIN_FILENO);
	dup2(devnull_out, STDOUT_FILENO);
	dup2(devnull_out, STDERR_FILENO);
	close(devnull_in);
	close(devnull_out);
}

int
main(int argc, char **argv)
{
	int c, index;
	char *config_file = strdup(LISTENER_RULES);

	char short_opts[] = "c:dh";
	struct option long_options[] = {
		{"config", required_argument, NULL, 'c'},
		{"debug",        no_argument, NULL, 'd'},
		{"help",         no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};

	/* check for arguments */
	while ((c = getopt_long(argc, argv, short_opts, long_options, &index)) != -1) {
		switch (c) {
			case 0:
			case '?':
				return 1;
			case 'c':
				free(config_file);
				config_file = strdup(optarg);
				break;
			case 'd':
				printf("Running in debug mode\n");
				ctx.debug_mode = 1;
				break;
			case 'h':
				show_usage(argv[0]);
				return 0;
			default:
				printf("invalid option %d\n", c);
				show_usage (argv[0]);
		}
	}

	/* opens the inotify device */
	ctx.inotify_fd = inotify_init();
	if (ctx.inotify_fd < 0) {
		perror("inotify_init");
		exit(EXIT_FAILURE);
	}

	/* read rules from listener.rules */
	ctx.watch_list = read_config(config_file);
	if (! ctx.watch_list) {
		free(config_file);
		exit(EXIT_FAILURE);
	}
	free(config_file);

	ctx.watch_hash = hashtable_create(ctx.watch_list);
	if (! ctx.watch_hash)
		exit(EXIT_FAILURE);

	/* install a signal handler to clean up memory */
	signal(SIGINT, suicide);

	if (ctx.debug_mode)
		listen_for_events();
	else {
		close_standard_descriptors();
		pid_t id = fork();
		if (id == 0)
			listen_for_events();
		else if (id < 0 ){
			perror("fork");
			exit(EXIT_FAILURE);
		}
	}
	exit(EXIT_SUCCESS);
}

/* vim:set ts=4 sts=0 sw=4: */
