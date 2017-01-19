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
#include "rules.h"

struct listener_ctx {
	struct directory_info *dir_info;
	int inotify_fd;
	int debug_mode;
};

static struct listener_ctx ctx;

#define debug_printf(fmt, args...)	if(ctx.debug_mode) printf(fmt, ##args)

void
suicide(int signum)
{
	struct directory_info *ptr;

	for (ptr=ctx.dir_info; ptr != NULL; ptr=ptr->next)
		regfree(&ptr->regex);
	free(ctx.dir_info);

	close(ctx.inotify_fd);
	exit(EXIT_SUCCESS);
}

void *
perform_action(void *thread_info)
{
	pid_t pid;
	char pathname[PATH_MAX];
	struct thread_info *info = (struct thread_info *) thread_info;
	struct directory_info *di = info->di;

	snprintf(pathname, sizeof(pathname), "%s/%s", di->pathname, info->offending_name);

	pid = fork();
	if (pid == 0) {
		char **exec_array, *cmd = di->exec_cmd;
		char exec_cmd[LINE_MAX];
		int len = strlen(cmd);
		int skipped = 0;

		memset(exec_cmd, 0, sizeof(exec_cmd));
		while (2) {
			int skip_bytes = 0;
			char *token = get_token(cmd, &skip_bytes, di->pathname, info);
			if (! token)
				break;

			cmd += skip_bytes;
			skipped += skip_bytes;

			strcat(exec_cmd, token);
			strcat(exec_cmd, " ");
			free(token);

			if (skipped >= len)
				break;
		}
		exec_array = (char **) malloc(4 * sizeof(char *));
		exec_array[0] = "/bin/sh";
		exec_array[1] = "-c";
		exec_array[2] = strdup(exec_cmd);
		exec_array[3] = NULL;
		if (ctx.debug_mode) {
			int i;
			for (i = 0; exec_array[i] != NULL; ++i)
				printf("token: '%s'\n", exec_array[i]);
		}
		free(info->di);
		free(info);
		execvp(exec_array[0], exec_array);

	} else if (pid > 0) {
		waitpid(pid, NULL, WUNTRACED);
	} else {
		perror("fork");
	}

	pthread_exit(NULL);
}

struct directory_info *
dir_info_index(struct directory_info *start, int wd)
{
	struct directory_info *ptr;

	for (ptr = start; ptr != NULL; ptr = ptr->next)
		if (ptr->wd == wd)
			return ptr;

	return NULL;
}
	
void
rebuild_tree(struct directory_info *start, struct directory_info *di)
{
	struct directory_info *ptr, *prev;
	struct directory_info *root = di->root; 

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

char *
mask_name(int mask)
{
	char buf[128];
	
	memset(buf, 0, sizeof(buf));
	
	if (mask & IN_ACCESS)
		snprintf(buf, sizeof(buf), "access");
	if (mask & IN_MODIFY)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "modify");
	if (mask & IN_ATTRIB)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "attrib");
	if (mask & IN_CLOSE_WRITE)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "close write");
	if (mask & IN_CLOSE_NOWRITE)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "close nowrite");
	if (mask & IN_OPEN)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "open");
	if (mask & IN_MOVED_FROM)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "moved from");
	if (mask & IN_MOVED_TO)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "moved to");
	if (mask & IN_CREATE)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "create");
	if (mask & IN_DELETE)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "delete");
	if (mask & IN_DELETE_SELF)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "delete self");
	if (mask & IN_MOVE_SELF)
		snprintf(buf, sizeof(buf), "%s%s", strlen(buf)?" | ":"", "move self");
	if (! strlen(buf))
		snprintf(buf, sizeof(buf), "unknown");

	return strdup(buf);
}

void
handle_events(struct inotify_event *ev)
{
	pthread_t tid;
	regmatch_t match;
	int ret;
	struct thread_info *info;
	struct stat status;
	char stat_pathname[PATH_MAX], offending_name[PATH_MAX];
	struct directory_info *di, *ptr;
	char *mask;
	int need_rebuild_tree = 0;

	for (ptr=ctx.dir_info; ptr != NULL; ptr=ptr->next) {
		di = dir_info_index(ptr, ev->wd);
		if (! di) {
			/* Couldn't find watch descriptor, so this is not a valid event */
			break;
		}

		if (ev->len > PATH_MAX)
			ev->len = PATH_MAX;

		if (di->recursive && ((SYS_MASK) & ev->mask))
			need_rebuild_tree = 1;
			 
		/* 
		 * first, check against the watch mask, since a given entry can be
		 * watched twice or even more times
		 */
		if (! (di->mask & ev->mask)) {
			debug_printf("event doesn't come from watch descriptor %d\n", di->wd);
			goto cleanup;
		}

		/* verify against regex if we want to handle this event or not */
		memset(offending_name, 0, sizeof(offending_name));
		snprintf(offending_name, ev->len, "%s", ev->name);
		ret = regexec(&di->regex, offending_name, 1, &match, 0);
		if (ret != 0) {
			debug_printf("event from watch descriptor %d, but regex doesn't match\n", di->wd);
			goto cleanup;
		}

		/* filter the entry by its type (dir|file) */
		snprintf(stat_pathname, sizeof(stat_pathname), "%s/%s", di->pathname, offending_name);
		ret = stat(stat_pathname, &status);
		if (ret < 0 && di->uses_entry_variable && ! (di->mask & IN_DELETE || di->mask & IN_DELETE_SELF)) {
			fprintf(stderr, "stat %s: %s\n", stat_pathname, strerror(errno));
			goto cleanup;
		}

		if (FILTER_DIRS(di->filter) && !FILTER_FILES(di->filter) && !S_ISDIR(status.st_mode)) {
			debug_printf("watch descriptor %d listens for DIRS rules, but event happened in another kind of object\n", di->wd);
			goto cleanup;
		}
		
		if (FILTER_FILES(di->filter) && !FILTER_DIRS(di->filter) && !S_ISREG(status.st_mode)) {
			debug_printf("watch descriptor %d listens for FILES rules, but event happened in another kind of object\n", di->wd);
			goto cleanup;
		}

		mask = mask_name(ev->mask);
		debug_printf("-> event on dir %s, watch %d\n", di->pathname, di->wd);
		debug_printf("-> filename:    %s\n", offending_name);
		debug_printf("-> event mask:  %#X (%s)\n\n", ev->mask, mask);
		free(mask);

		/* launches a thread to deal with the event */
		info = (struct thread_info *) malloc(sizeof(struct thread_info));
		info->di = (struct directory_info *) malloc(sizeof(struct directory_info));
		memcpy(info->di, di, sizeof(struct directory_info));
		snprintf(info->offending_name, sizeof(info->offending_name), "%s", offending_name);
		pthread_create(&tid, NULL, perform_action, (void *) info);

		/* event handled, that's all! */
		
cleanup:
		if (need_rebuild_tree) {
			rebuild_tree(ctx.dir_info, di); 
		}
		break;
	}
}

void
listen_for_events(void)
{
	size_t n;
	int evnum;
	char buf[128 * (sizeof(struct inotify_event) + 16)];

	while (2) {
		select_on_inotify();
		n = read(ctx.inotify_fd, buf, sizeof(buf));
		if (n < 0) {
			perror("read");
			break;
		} else if (n == 0) {
			continue;
		}

		evnum = 0;
		while (evnum < n) {
			struct inotify_event *event = (struct inotify_event *) &buf[evnum];
			handle_events(event);
			evnum += sizeof(struct inotify_event) + event->len;
		}
	}
}

struct directory_info *
monitor_directory(int i, struct directory_info *di)
{
	uint32_t mask, current_mask, my_root_mask;
	struct directory_info *ptr, *my_root;

	int walk_tree(const char *file, const struct stat *sb, int flag, struct FTW *li) {
		struct directory_info *di;

		if (flag != FTW_D) /* isn't a subdirectory */
			return 0;
		if (li->level > my_root->recursive)
			return FTW_SKIP_SUBTREE;

		/*
		 * replicate the parent's exec_cmd, uses_entry_variable, mask, filter,
		 * regex and recursive members
		 */
		di = (struct directory_info *) calloc(1, sizeof(struct directory_info));
		memcpy(di, my_root, sizeof(*di));

		/* only needs to differentiate on the pathname, regex and watch descriptor */
		snprintf(di->pathname, sizeof(di->pathname), "%s", file);
		regcomp(&di->regex, di->regex_rule, REG_EXTENDED);
		di->wd = inotify_add_watch(ctx.inotify_fd, file, my_root_mask | SYS_MASK);

		my_root->next = di;
		my_root = di;

		debug_printf("[recursive] Monitoring %s on watch %d\n", di->pathname, di->wd);
		return FTW_CONTINUE;
	}

	/* 
	 * Check for the existing entries if this directory is already being listened.
	 * If we have a match, then we must append a new mask instead of replacing the
	 * current one.
	 */
	for (current_mask=0, ptr=ctx.dir_info; ptr != NULL; ptr=ptr->next) {
		if (! strcmp(ptr->pathname, di->pathname))
			current_mask |= ptr->mask;
	}

	mask = di->mask | current_mask;
	di->root = di; //pointer to root diretory
	
	if (di->recursive) {
		my_root = di;
		my_root_mask = mask;
		nftw(di->pathname, walk_tree, 1024, FTW_ACTIONRETVAL);
		di = my_root;
	} else {
		di->wd = inotify_add_watch(ctx.inotify_fd, di->pathname, mask);
		debug_printf("Monitoring %s on watch %d\n", di->pathname, di->wd);
	}
	return di;
}

void
show_usage(char *program_name)
{
	fprintf(stderr, "Usage: %s [options]\n\nAvailable options are:\n"
			"-c, --config FILE    Take config options from FILE\n"
			"-d, --debug          Run in the foreground\n"
			"-h, --help           This help\n", program_name);
}

int
main(int argc, char **argv)
{
	int ret, c, index;
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
	ctx.dir_info = assign_rules(config_file, &ret);
	if (ret < 0) {
		free(config_file);
		exit(EXIT_FAILURE);
	}
	free(config_file);

	/* install a signal handler to clean up memory */
	signal(SIGINT, suicide);

	if (ctx.debug_mode)
		listen_for_events();
	else {
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
