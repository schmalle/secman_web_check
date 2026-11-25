# Select a reproducible review scope

## Latest committed change

Run trusted local Git from the intended repository root. Confirm the discovered root is the intended target, especially for directories nested inside an unrelated checkout. Disable paging, replacement refs, lazy fetching and optional writes. Use local object reads only. Disable external diff and text conversion. Do not use checkout, submodule initialization, LFS smudging, or repository helpers.

A shell example for Git versions supporting these settings follows. Supply a trusted Git binary through PATH. Run in a shell without repository-supplied startup configuration.

```sh
export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_OPTIONAL_LOCKS=0
export GIT_ALLOW_PROTOCOL=''
head_oid=$(git rev-parse --verify 'HEAD^{commit}') || exit 1
git cat-file -p "$head_oid" | sed '/^$/q'       # inspect commit headers only
```

Read the first literal parent header before the blank separator. A shallow boundary may hide its parent from revision traversal even though the commit object names it. If a parent header exists, set base_oid to its object ID and verify availability with `git cat-file -e "${base_oid}^{commit}"`. If missing, identify that object and stop commit comparison. If there is no parent header, use the root form below. An unborn HEAD cannot supply a commit review.

```sh
# Ordinary or merge commit, against its first parent
git --no-pager diff --no-ext-diff --no-textconv --ignore-submodules=none --name-status -z "$base_oid" "$head_oid" --
# Root commit, compared to an empty tree
git --no-pager diff-tree --root -r --no-commit-id --name-status -z "$head_oid" --
```

Consume NUL-delimited filenames as data. Read committed file contents with `git cat-file blob "${head_oid}:$path"` and the corresponding base object for earlier evidence. Number lines in those blobs. Use the old location on the base side of a rename or deletion. Inspect file modes before reading: symlink blobs contain link text, and gitlinks identify a separate commit. Treat missing objects, submodule contents and LFS pointers as coverage limits. Keep staged, unstaged and untracked work out of this mode.

## Full folder

Walk the supplied directory directly. A tracked-file list misses local deployment inputs. One inventory option is `find -P . -name .git -prune -o -type f -print0` from the target root. Inventory symlinks separately if they affect packaging, and do not follow them. Read regular text files only, including dotfiles and local configuration. Handle filenames as literal arguments. Report unreadable paths and exclusions. Group large dependency caches, build outputs and binaries as exclusions after checking whether they contain the only available deployed configuration or source. Record working-tree state only when safely available. Label citations as working-folder evidence even if a HEAD identifier is available.
