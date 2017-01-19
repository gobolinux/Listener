# GoboLinux Listener

Listener is a daemon that watchs for file system events. It has been
designed so that user-configurable commands can be triggered upon
changes to the file system.

Such commands are described as rules that also include the directory
to watch, which kind of file objects to watch, and a regular expression
that whitelists the file names that are subject to processing.

# Sample rule file

The following example holds a rule that watches for DELETE events on
*/Programs*. Regular files are ignored; the rule only looks at DELETE
events that remove a subdirectory of */Programs*. A *RECURSIVE_DEPTH*
value of 1 would watch a single level below */Programs*. That is, the
removal of */Programs/Foo* would trigger the rule. A value of 2 would
indicate that the removal of */Programs/Foo/Version* would trigger that
rule instead. The actual command to execute is described on SPAWN.

```shell
{
	TARGET          = /Programs
	WATCHES         = DELETE
	SPAWN           = find /System/Index /System/Settings | RemoveBroken >> /var/log/Listener-RemoveBroken.log
	LOOKAT          = DIRS
	ACCEPT_REGEX    = ^[-+_[:alnum:]]+
	RECURSIVE_DEPTH = 1
}
```
