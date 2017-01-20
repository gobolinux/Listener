/*
 * Listener - Listens for specific directories events and take actions 
 * based on rules specified by the user.
 *
 * Copyright (c) 2005,2006  Lucas C. Villa Real <lucasvr@gobolinux.org>
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

#define EAT_SPACES(buf,ptr) for(ptr=buf; *ptr && (*ptr == ' ' || *ptr == '\t'); ptr++)

char *
get_token(char *cmd, int *skip_bytes, char *pathname, struct thread_info *info)
{
	int wi, j, i=0, skip=0;
	char line[LINE_MAX], work_line[LINE_MAX];
	char *entry_ptr, *ptr;

	if (! cmd || ! strlen(cmd)) {
		*skip_bytes = 0;
		return NULL;
	}

	memset(line, 0, sizeof(line));
	memset(work_line, 0, sizeof(work_line));

	while (isblank(*cmd)) {
		cmd++;
		skip++;
	}
	while (*cmd && ! isblank(*cmd)) {
		line[i++] = *(cmd++);
		skip++;
	}
	*skip_bytes = skip;

	if ((entry_ptr = strstr(line, "$ENTRY_RELATIVE"))) {
		for (wi=0, ptr=line; ptr != entry_ptr; ptr++)
			work_line[wi++] = (*ptr)++;
		for (j=0; j<strlen(info->offending_name); ++j)
			work_line[wi++] = info->offending_name[j];

		/* skip '$ENTRY_RELATIVE' and copy the remaining data */
		for (ptr+=15; *ptr; ptr++)
			work_line[wi++] = (*ptr)++;
		strcpy(line, work_line);
	}

	if ((entry_ptr = strstr(line, "$ENTRY"))) {
		for (wi=0, ptr=line; ptr != entry_ptr; ptr++)
			work_line[wi++] = (*ptr)++;
		for (j=0; j<strlen(pathname); ++j)
			work_line[wi++] = pathname[j];
		work_line[wi++] = '/';
		for (j=0; j<strlen(info->offending_name); ++j)
			work_line[wi++] = info->offending_name[j];

		/* skip '$ENTRY' and copy the remaining data */
		for (ptr+=6; *ptr; ptr++)
			work_line[wi++] = (*ptr)++;
		strcpy(line, work_line);
	}
	return strdup(line);
}

char *
read_line(char *buf, ssize_t size, FILE *fp)
{
	char *ptr;

	memset(buf, 0, size);
	fgets(buf, size, fp);
	if (! strlen(buf))
		return NULL;
	EAT_SPACES(buf,ptr);
	if (*ptr && buf[strlen(buf)-1] == '\n')
		buf[strlen(buf)-1] = 0;
	if (! *ptr || *ptr == '#')
		return NULL;
	return ptr;
}

int
expect_rule_start(FILE *fp)
{
	char *token, *ptr;
	char buf[LINE_MAX];

	while (! feof (fp)) {
		ptr = read_line(buf, sizeof(buf), fp);
		if (!ptr)
			continue;
		token = strtok(ptr, " \t");
		if (token == NULL)
			continue;
		if (! strcmp (token, "{"))
			return 0;
		break;
	}
	return -1;
}

int
expect_rule_end(FILE *fp)
{
	char *token, *ptr;
	char buf[LINE_MAX];

	while (! feof (fp)) {
		ptr = read_line(buf, sizeof(buf), fp);
		if (!ptr)
			continue;
		token = strtok(ptr, " \t");
		if (token == NULL)
			continue;
		if (! strcmp(token, "}"))
			return 0;
		fprintf(stderr, "Error: expected rule's end marker '}', but found '%s' instead.\n", ptr);
		break;
	}
	return -1;
}

char *
get_rule_for(char *entry, FILE *fp)
{
	char *ptr, *token = NULL;
	char buf[LINE_MAX];

	while (! feof (fp)) {
		ptr = read_line(buf, sizeof(buf), fp);
		if (!ptr)
			continue;
		if ((*ptr == '{') || (*ptr == '}'))
			return NULL;
		break;
	}

	/* check for ENTRY match */
	if (! strstr(ptr, entry))
		return NULL;

	token = strtok(buf, "=");
	if (! token)
		return NULL;

	/* get the RULE associated with ENTRY */
	token = token + strlen(token) + 1;
	while (*token == '\t' || *token == ' ')
		token++;

	if (! token)
		return NULL;

	if (token[strlen(token)-1] == '\n')
		token[strlen(token)-1] = '\0';

	return strdup(token);
}

int
parse_masks(char *masks)
{
	int ret = IN_DONT_FOLLOW;

	if ((strstr(masks, "ACCESS")))
		ret |= IN_ACCESS;
	if ((strstr(masks, "MODIFY")))
		ret |= IN_MODIFY;
	if ((strstr(masks, "ATTRIB")))
		ret |= IN_ATTRIB;
	if ((strstr(masks, "CLOSE_WRITE")))
		ret |= IN_CLOSE_WRITE;
	if ((strstr(masks, "CLOSE_NOWRITE")))
		ret |= IN_CLOSE_NOWRITE;
	if ((strstr(masks, "OPEN")))
		ret |= IN_OPEN;
	if ((strstr(masks, "MOVED_FROM")))
		ret |= IN_MOVED_FROM;
	if ((strstr(masks, "MOVED_TO")))
		ret |= IN_MOVED_TO;
	if ((strstr(masks, "CREATE")))
		ret |= IN_CREATE;
	if ((strstr(masks, "DELETE")))
		ret |= IN_DELETE;
	if ((strstr(masks, "DELETE_SELF")))
		ret |= IN_DELETE_SELF;
	if ((strstr(masks, "MOVE_SELF")))
		ret |= IN_MOVE_SELF;

	return ret;
}

watch_t *
assign_rules(char *config_file, int *retval)
{
	int i, n, ret;
	FILE *fp;
	char *token;
	watch_t *watch_list, *watch, *last;

	/* we didn't have success on the operation yet */
	*retval = -1;
	
	fp = fopen(config_file, "r");
	if (! fp) {
		fprintf(stderr, "%s: %s\n", config_file, strerror(errno));
		return NULL;
	}

	/* read how many rules we have */
	n = 0;
	while (! feof(fp)) {
		char *ptr;
		char buf[LINE_MAX], pathname[LINE_MAX];

		ptr = read_line(buf, sizeof(buf), fp);
		if (!ptr)
			continue;
		if (*ptr == '{')
			n++;
		else if (strstr(ptr, "TARGET")) {
			char *token = strtok(ptr, " \t");
			token = strtok(NULL, " \t");
			token = strtok(NULL, " \t");
			if (! token) {
				fprintf(stderr, "Error: one or more TARGET entries don't have a value assigned to\n");
				return NULL;
			}
			token[strlen(token)-1] = '\0';
			sprintf(pathname, token);
		}
	}

	/* there are no rules at all */
	if (n == 0) {
		*retval = 0;
		return NULL;
	}

	/* this is the linked list's first element */
	watch_list = (watch_t *) calloc(1, sizeof(watch_t));
	if (! watch_list) {
		perror("calloc");
		return NULL;
	}

	/* and we work always on this pointer */
	watch = watch_list;

	rewind(fp);
	
	/* register the pathname */
	for (i = 0; i < n; ++i) {	
		/* expects to find the '{' character */
		if ((expect_rule_start(fp)) < 0) {
			fprintf(stderr, "Error: could not find the rule's start marker '{'\n");
			return NULL;
		}

		/* populates the watch_entry struct */
		token = get_rule_for("TARGET", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing TARGET entry\n", i+1);
			return NULL;
		}

		if (i > 0) {
			watch_t *old = watch;
			
			/* watch is no more a pointer to watch_list */
			watch = (watch_t *) calloc(1, sizeof(watch_t));
			if (! watch) {
				perror("calloc");
				return NULL;
			}
			
			old->next = watch;
		}
		snprintf(watch->pathname, sizeof(watch->pathname), token);
		free(token);
		
		/* register the masks */
		token = get_rule_for("WATCHES", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing WATCHES entry\n", i+1);
			return NULL;
		}

		watch->mask = parse_masks(token);
		if (watch->mask == EMPTY_MASK) {
			fprintf(stderr, "Error on rule #%d: invalid WATCH %s\n", i+1, token);
			return NULL;
		}
		free(token);

		/* get the exec command */
		token = get_rule_for("SPAWN", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing SPAWN command\n", i+1);
			return NULL;
		}
		snprintf(watch->exec_cmd, sizeof(watch->exec_cmd), token);

		/* remember if the SPAWN command makes reference to the $ENTRY variable */
		watch->uses_entry_variable = (strstr(token, "$ENTRY") == NULL ? 0 : 1);
		free(token);

		/* get the filters */
		token = get_rule_for("LOOKAT", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing LOOKAT entry\n", i+1);
			return NULL;
		}

		if (! strcasecmp(token, "DIRS"))
			watch->filter = S_IFDIR;
		else if (! strcasecmp(token, "FILES"))
			watch->filter = S_IFREG;
		else if (! strcasecmp(token, "SYMLINKS"))
			watch->filter = S_IFLNK;
		else {
			fprintf(stderr, "Error on rule #%d: invalid LOOKAT option %s\n", i+1, token);
			free(token);
			return NULL;
		}
		free(token);

		/* get the regex rule */
		token = get_rule_for("ACCEPT_REGEX", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing ACCEPT_REGEX entry\n", i+1);
			return NULL;
		}

		snprintf(watch->regex_rule, sizeof(watch->regex_rule), "%s", token);
		free(token);

		ret = regcomp(&watch->regex, watch->regex_rule, REG_EXTENDED);
		if (ret != 0) {
			char err_msg[256];
			regerror(ret, &watch->regex, err_msg, sizeof(err_msg) - 1);
			fprintf(stderr, "Regex error \"%s\": %s\n", watch->regex_rule, err_msg);
			return NULL;
		}

		/* disabled until implemented correctly */
		watch->recursive = 0;

		/* get the recursive flag */
		token = get_rule_for("RECURSIVE_DEPTH", fp);
		if (! token) {
			fprintf(stderr, "Error on rule #%d: missing RECURSIVE_DEPTH entry\n", i+1);
			return NULL;
		}

		if (! strcasecmp(token, "NO"))
			watch->recursive = 0;
		else if (! strcasecmp(token, "YES"))
			watch->recursive = MAX_RECUSIVE_DEPTH;
		else
			watch->recursive = atoi(token);
			
		if (watch->recursive < 0 || watch->recursive > MAX_RECUSIVE_DEPTH) {
			fprintf(stderr, "Error on rule #%d: invalid RECURSIVE_DEPTH option %s\n", i+1, token);
			free(token);
			return NULL;
		}
		free(token);

		/* expects to find the '}' character */
		if ((expect_rule_end(fp)) < 0)
			return NULL;

		/* create the monitor rules */
		last = monitor_directory(i+1, watch);
		if (last == NULL)
			return NULL;
			
		watch = last;
	}

	*retval = 0;
	
	fclose(fp);
	return watch_list;
}
