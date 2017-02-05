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
#include <json-c/json.h>
#include "listener.h"
#include "rules.h"

#define MIN(x,y) (((x)<(y)) ? (x):(y))

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

int
parse_masks(const char *masks)
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

void print_json_value(json_object *jobj)
{
	enum json_type type = json_object_get_type(jobj);
	switch (type) {
		case json_type_boolean:
			printf("json_type_boolean, ");
			printf("value: %s\n", json_object_get_boolean(jobj)? "true": "false");
			break;
		case json_type_double:
			printf("json_type_double, ");
			printf("value: %lf\n", json_object_get_double(jobj));
			break;
		case json_type_int:
			printf("json_type_int, ");
			printf("value: %d\n", json_object_get_int(jobj));
			break;
		case json_type_string:
			printf("json_type_string, ");
			printf("value: %s\n", json_object_get_string(jobj));
			break;
		default:
			fprintf(stderr, "Unexpected data type %d\n", type);
	}
}

static json_bool
map_description(char *key, json_object *val, watch_t *watch)
{
	return TRUE;
}

static json_bool
map_target(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		int n = snprintf(watch->pathname, sizeof(watch->pathname)-1, strval);
		if (n < 0) {
			fprintf(stderr, "%s: failed to format string\n", strval);
			return FALSE;
		}
		watch->pathname[n] = '\0';
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_watches(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		watch->mask = parse_masks(strval);
		if (watch->mask == EMPTY_MASK) {
			fprintf(stderr, "%s: invalid mask(s)\n", strval);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_spawn(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		int n = snprintf(watch->exec_cmd, sizeof(watch->exec_cmd)-1, strval);
		if (n < 0) {
			fprintf(stderr, "%s: failed to format string\n", strval);
			return FALSE;
		}
		/* TODO: $ENTRY */
		watch->exec_cmd[n] = '\0';
		watch->uses_entry_variable = strstr(strval, "$ENTRY") == NULL ? 0 : 1;
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_lookat(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		if (! strcasecmp(strval, "DIRS"))
			watch->filter = S_IFDIR;
		else if (! strcasecmp(strval, "FILES"))
			watch->filter = S_IFREG;
		else if (! strcasecmp(strval, "SYMLINKS"))
			watch->filter = S_IFLNK;
		else {
			fprintf(stderr, "%s: invalid value for 'lookat' option\n", strval);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_regex(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		int n = snprintf(watch->regex_rule, sizeof(watch->regex_rule)-1, "%s", strval);
		if (n < 0) {
			fprintf(stderr, "%s: failed to format string\n", strval);
			return FALSE;
		}

		n = regcomp(&watch->regex, watch->regex_rule, REG_EXTENDED);
		if (n != 0) {
			char err_msg[256];
			regerror(n, &watch->regex, err_msg, sizeof(err_msg) - 1);
			fprintf(stderr, "\"%s\": %s\n", watch->regex_rule, err_msg);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_depth(char *key, json_object *val, watch_t *watch)
{
	const char *strval = json_object_get_string(val);
	if (strval) {
		watch->recursive = atoi(strval);
		if (watch->recursive < 0 || watch->recursive > MAX_RECUSIVE_DEPTH) {
			fprintf(stderr, "%s: invalid depth\n", strval);
			return FALSE;
		}
		return TRUE;
	}
	return FALSE;
}

static json_bool
map_keyvalue(int rulenr, char *key, json_object *val, watch_t *watch)
{
	struct map_struct {
		char *key;
		json_bool (*mapper)(char *, json_object *, watch_t *);
	};
	struct map_struct map[] = {
		{ "description", map_description },
		{ "target",      map_target },
		{ "watches",     map_watches },
		{ "spawn",       map_spawn },
		{ "lookat",      map_lookat },
		{ "regex",       map_regex },
		{ "depth",       map_depth },
		{ NULL,          NULL }
	}, *ptr;

	for (ptr=map; ptr->key; ptr++) {
		if (!strcasecmp(key, ptr->key))
			return ptr->mapper(key, val, watch);
	}

	return FALSE;
}

static json_bool
watch_sanity_check(watch_t *watch)
{
#if 0
	if (!watch->description[0]) {
		fprintf(stderr, "Config file error: 'description' option is not set\n");
		return FALSE;
	}
#endif
	if (!watch->pathname[0]) {
		fprintf(stderr, "Config file error: 'target' option is not set\n");
		return FALSE;
	}
	if (!watch->mask) {
		fprintf(stderr, "Config file error: 'watches' option is not set\n");
		return FALSE;
	}
	if (!watch->exec_cmd[0]) {
		fprintf(stderr, "Config file error: 'spawn' option is not set\n");
		return FALSE;
	}
	if (!watch->filter) {
		fprintf(stderr, "Config file error: 'lookat' option is not set\n");
		return FALSE;
	}
#if 0
	if (!watch->regex_rule[0]) {
		fprintf(stderr, "Config file error: 'regex' option is not set\n");
		return FALSE;
	}
	if (watch->recursive < 0) {
		fprintf(stderr, "Config file error: 'depth' option is not set\n");
		return FALSE;
	}
#endif
	return TRUE;
}

static json_bool
read_json_object(int rulenr, json_object *jobj, watch_t *watch)
{
	json_bool ret = TRUE;
	json_object_object_foreach(jobj, key, val) {
		enum json_type type = json_object_get_type(val);
		switch (type) {
			case json_type_string:
				ret = map_keyvalue(rulenr, key, val, watch);
				break;
			default:
				fprintf(stderr, "Unexpected JSON object found:\n");
				print_json_value(val);
				ret = FALSE;
		}
		if (ret == FALSE)
			break;
	}
	if (ret == TRUE)
		ret = watch_sanity_check(watch);
	return ret;
}

static watch_t *
read_json_array(json_object *jobj, char *key)
{
	json_object *jarray = jobj;
	watch_t *head = NULL, *prev = NULL;

	if (key && !json_object_object_get_ex(jobj, key, &jarray))
		return NULL;

	for (int i=0; i<json_object_array_length(jarray); ++i) {
		json_object *entry = json_object_array_get_idx(jarray, i);
		enum json_type type = json_object_get_type(entry);
		if (type != json_type_object) {
			fprintf(stderr, "Expected a JSON object, found something different:\n");
			print_json_value(entry);
			return NULL;
		}

		watch_t *watch = (watch_t *) calloc(1, sizeof(watch_t));
		if (! watch) {
			perror("calloc");
			return NULL;
		}
		if (prev)
			prev->next = watch;
		if (head == NULL)
			head = watch;

		if (read_json_object(i+1, entry, watch) == FALSE)
			return NULL;

		prev = monitor_directory(i+1, watch);
	}

	return head;
}

watch_t *
read_config(char *config_file)
{
	json_object *jobj = json_object_from_file(config_file);
	if (jobj) {
		json_object_object_foreach(jobj, key, val) {
			enum json_type type = json_object_get_type(val);
			if (type != json_type_array) {
				fprintf(stderr, "Config file parsing error\n");
				return NULL;
			}
			/* the config file must have a single top-level array */
			watch_t *watch = read_json_array(jobj, key);
			if (watch == NULL) {
				fprintf(stderr, "Config file parsing error\n");
				return NULL;
			}
			return watch;
		}
	}
	return NULL;
}
