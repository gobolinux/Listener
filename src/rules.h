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
#ifndef LISTENER_RULES_H
#define LISTENER_RULES_H 1

char    *get_token(char *cmd, int *skip_bytes, char *pathname, struct thread_info *info);
char    *get_rule_for(char *entry, FILE *fp);
watch_t *assign_rules(char *config_file, int *retval);
int      expect_rule_start(FILE *fp);
int      expect_rule_end(FILE *fp);
int      parse_masks(char *masks);

#endif /* LISTENER_RULES_H */
