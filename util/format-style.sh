#!/bin/bash

# Format files in a commit range
# usage: format-style.sh [commit range]
# If not commit range is given, format the entire tree
# Commit range should be specified in format suitable for git diff

COMMITS=$1

trap "rm -f $FORMATFILES" EXIT

FORMATFILES=$(mktemp /tmp/clang.files.XXXXXX)


# Find the top of the source tree
SRCTOP=$(git rev-parse --show-toplevel 2>/dev/null)

if [ -z "$SRCTOP" ]
then
    echo "Can't find top of source tree, assuming current directory"
    SRCTOP=$PWD
fi

# Make sure we can find our format file
if [ ! -f $SRCTOP/clang-format ]
then
    echo "Format file $SRCTOP/clang-format not found"
    exit 1
fi

# Make sure the tree is clean
CLEANSTAT=$(git status --porcelain --ignored)

if [ -n "$CLEANSTAT" ]
then
    echo "Tree is not clean.  The following files/dirs should be removed"
    echo $CLEANSTAT
    exit 1
fi

# Build our files list
if [ -z "$COMMITS" ]
then
    find $SRCTOP -name '*.[ch]' > $FORMATFILES
else
    # search for .[ch] files in the diff specified by COMMITS
    for i in $(git diff $COMMITS | diffstat | awk '/^ .*\|/ {print $1}')
    do
        echo $i | grep -q "^.*\.[ch]$"
        if [ $? -eq 0 ]
        then
            echo $i >> $FORMATFILES
        else
            echo "Skipping $i"
        fi
    done
fi

# run clang-format
clang-format --verbose -i --style=file:$SRCTOP/clang-format @$FORMATFILES

