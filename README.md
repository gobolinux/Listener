# GoboLinux Listener

Listener is a daemon that watchs for file system events. It has been
designed so that user-configurable commands can be triggered upon
changes to the file system.

Such commands are described as rules that also include the directory
to watch, which kind of file objects to watch, and a regular expression
that whitelists the file names that are subject to processing.

# Listener.conf format

Listener's config file accepts multiple rules. Each rule must be enclosed
with brackets ("{" and "}") following a JSON syntax and needs to contain
the following sequence of keys:
    
- **description**: Optional field. Holds a textual description of the rule.

- **target**: pathname to listen.

- **watches**: file system / inotify events to watch. The following flags are
  recognized and may be combined with the OR ("|") operator:
  - *ACCESS*: file  has been accessed on the watched directory
  - *MODIFY*: file has been modified on the watched directory
  - *ATTRIB*: attributes (e.g., permissions, timestamps, ownership) have changed
  - *CLOSE_WRITE*: file has been opened for writing and has now been closed
  - *CLOSE_NOWRITE*: file or directory has been opened for reading only and has now been closed
  - *OPEN*: file or directory was opened
  - *MOVED_FROM*: a file or directory has been moved from the watched directory to somewhere else
  - *MOVED_TO*: a file or directory has been moved to the watched directory
  - *CREATE*: a file or directory was created on the watched directory
  - *DELETE*: a file or directory has been deleted
  - *DELETE_SELF*: watched file/directory has been deleted itself
  - *MOVE_SELF*: watched file/directory has been moved itself
  
- **spawn**: shell command to invoke when the event is triggered. In special,
  the string $ENTRY can be used to represent the file or directory name that
  triggered the event.

- **lookat**: file types to consider under the watched directory. The following
  types are recognized and may be combined with the OR ("|") operator:
  - *DIRS*: directories
  - *FILES*: regular files
  - *SYMLINKS*: symbolic links

- **regex**: Optional field. Describes a regular expression that indicates the
  file name patterns to process. This is useful if you are watching a directory
  that holds both MP3 and AVI files, for instance, but want to have a listener
  rule that only processes one of the two. If not set, all files and directories
  under the watched directory will be processed.
  
- **depth**: Optional field. Defines how many levels below TARGET to watch. A 
  depth of 0 (the default) will look for events on file system objects that are
  immediate children of TARGET. A depth of 1 will look for events on objects that
  are both immediate children of TARGET and also children of its 1st level
  subdirectories, and so on.

# Sample rule file

The following example holds a rule that watches for DELETE events on
*/Programs*. Regular files are ignored; the rule only looks at DELETE
events that remove a subdirectory of */Programs*. A *depth*
value of 1 would watch a single level below */Programs*. That is, the
removal of */Programs/Foo* would trigger the rule. A value of 2 would
indicate that the removal of */Programs/Foo/Version* would also trigger
that rule. The actual command to execute is described on *spawn*.

```shell
{
  "rules": [ {
    "description": "Removes broken links when a directory under /Programs is deleted",
    "target":      "/Programs",
    "watches":     "DELETE|DELETE_SELF",
    "spawn":       "/System/Index/share/Listener/RemoveBrokenTask",
    "lookat":      "DIRS",
    "regex":       "^[-+_[:alnum:]]+",
    "depth":       "1"
  } ]
}
```
