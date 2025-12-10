#!/bin/bash

#######################################################################
# Sample script to drive semi-automatic reformatting of in flight PRs
#
# This script will (attempt) to rebase a provided branch onto the post
# format tag of the target branch
#
# Input arguments:
# $1 - the target branch you wish to rebase to, aliased as ${TARGET_BRANCH}
# $2 - the branch you wish to rebase, aliased as ${REBASE_BRANCH}
#
# Outputs:
# On successfully running, this script will leave you checked out on
# a branch named ${2}-reformat with all the commits of your ${2} branch,
# reformatted with clang-format using our clang-format file, and rebased
# to the $VERSION-POST-CLANG-FORMAT-WEBKIT tag on the target branch specified
#
# Assumptions:
# 1) It assumes that you are in the root of the git tree you are working with
# when executed
#
# 2) It assumes that the target branch specified has been mass-reformatted
# To our clang format styles.  This currently includes the following branches:
#  master
#  openssl-3.6
#  openssl-3.5
#  openssl-3.4
#  openssl-3.3
#  openssl-3.0
#
# Method of operation:
#
# 1) Create a temporary branch, ${REBASE_BRANCH}-rebase, a clone of ${REBASE_BRANCH}
#
# 2) ${REBASE_BRANCH}-rebase is rebased to be rooted at $VERSION-PRE-CLANG-FORMAT-WEBKIT
# This attempts to ensure that will be no conflicts other than the reformatting changes.
# If conflicts are detected, the script aborts, and informs the user that the branch should
# be manually rebased onto $VERSION-PRE-CLANG-FORMAT-WEBKIT
#
# 3) build a list of commits in ${REBASE_BRANCH}-rebase, named commits-to-reformat
#
# 3) for each commit in commits-to-reformat:
#   a) create a temporary-branch $COMMIT-reformat, rooted at $COMMIT
#   b) checks out the branch $COMMIT-reformat
#   c) runs clang-format on the .c/.h/.c.in/.h.in files modified by that
#      commit
#   d) ammends the commit on this branch with those formatting changes in (c)
#   This provides a series of commits that contain the ${REBASE_BRANCH} changes
#   reformatted to meet our style, including the context surrounding them
#
# 4) Create a branch ${REBASE_BRANCH}-reformat, rooted at $VERSION-PRE-CLANG-FORMAT-WEBKIT
#
# 5) For each commit in commits-to-reformat
#   a) get the reformatted commit from the corresponding branch created in step (3) and cherry
#   pick it to the ${REBASE_BRANCH}-reformat branch
#
# 6) Rebase the ${REBASE_BRANCH}-reformat branch to the $VERSION-POST-CLANG-FORMAT-WEBKIT
#
# 7) Clean up all the temporary branches, temp directories etc
#######################################################################

START_COMMIT=$(git rev-parse HEAD)
ERROR_ENCOUNTERED=yes

# Cleanup function to be run on exit
cleanup() {
    git rebase --abort >/dev/null 2>&1
    git checkout $START_COMMIT >/dev/null 2>&1
    git branch -D $REBASE_BRANCH-rebase
    if [ "$ERROR_ENCOUNTERED" == "yes" ]; then
        git branch -D $REBASE_BRANCH-reformat >/dev/null 2>&1
    else
        git checkout ${REBASE_BRANCH}-reformat >/dev/null 2>&1
    fi
    if [ -f $TMPDIR/commits-to-reformat ]; then
        for COMMIT in $(cat $TMPDIR/commits-to-reformat); do
            git branch -D ${COMMIT}-reformat >/dev/null 2>&1
        done
    fi
    rm -rf $TMPDIR
}

trap cleanup EXIT

TMPDIR=$(mktemp -d /tmp/reformat.XXXXXX)

TARGET_BRANCH=$1
REBASE_BRANCH=$2
PRE_FORMAT_TAG=""
POST_FORMAT_TAG=""

get_reformat_commit_tags() {
    case "$TARGET_BRANCH" in
    "master")
        PRE_FORMAT_TAG=4.0-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=4.0-POST-CLANG-FORMAT-WEBKIT
        ;;
    "openssl-3.6")
        PRE_FORMAT_TAG=3.6-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=3.6-POST-CLANG-FORMAT-WEBKIT
        ;;
    "openssl-3.5")
        PRE_FORMAT_TAG=3.5-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=3.5-POST-CLANG-FORMAT-WEBKIT
        ;;
    "openssl-3.4")
        PRE_FORMAT_TAG=3.4-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=3.4-POST-CLANG-FORMAT-WEBKIT
        ;;
    "openssl-3.3")
        PRE_FORMAT_TAG=3.3-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=3.3-POST-CLANG-FORMAT-WEBKIT
        ;;
    "openssl-3.0")
        PRE_FORMAT_TAG=3.0-PRE-CLANG-FORMAT-WEBKIT
        POST_FORMAT_TAG=3.0-POST-CLANG-FORMAT-WEBKIT
        ;;
    *)
        echo "No reformatted branch found"
        exit 1
        ;;
    esac 
}

git clean -f -d -x
git reset --hard

# figure out where our branch to rebase starts
BASE_COMMIT=$(git merge-base $TARGET_BRANCH $REBASE_BRANCH)

# get our pre/post format commit tags
get_reformat_commit_tags

# create a temporary rebase branch
echo "creating $REBASE_BRANCH-rebase"
git checkout -b $REBASE_BRANCH-rebase $REBASE_BRANCH

# rebase the rebase branch to the pre-reformat tag
echo "Rebasing $REBASE_BRANCH-rebase onto $PRE_FORMAT_TAG"
git rebase $BASE_COMMIT $REBASE_BRANCH-rebase --onto $PRE_FORMAT_TAG
if [ $? -ne 0 ]; then
    echo "Rebase of requested branch $REBASE_BRANCH failed"
    echo "Please rebase $REBASE_BRANCH manually, with this command:"
    echo "git rebase $BASE_COMMIT $REBASE_BRANCH --onto $PRE_FORMAT_TAG"
    exit 1
fi

# Need to recompute the BASE_COMMIT after the above rebase
BASE_COMMIT=$(git rev-parse $PRE_FORMAT_TAG)

# Collect a list of commits in the -rebase branch to massage into the reformatted file
git log --reverse --format=%H $BASE_COMMIT..$REBASE_BRANCH-rebase > $TMPDIR/commits-to-reformat

# For each commit in the rebase...
for COMMIT in $(cat $TMPDIR/commits-to-reformat); do
    echo "Handling commit $COMMIT"
    # Create a directory to store some temp files for this commit
    mkdir -p $TMPDIR/reformatted-patches/$COMMIT

    # Checkout a unique branch for that commit
    git checkout -b ${COMMIT}-reformat $COMMIT

    # Collect the files from this commit we want to reformat
    git show --name-only | grep -E ".*\.c$|.*\.h$|.*\.c\.in$|.*\.h\.in$" > $TMPDIR/reformatted-patches/$COMMIT/raw-files-to-format

    # Figure out if we have any files that need reformatting
    FILE_COUNT=$(wc -l $TMPDIR/reformatted-patches/$COMMIT/raw-files-to-format | awk '{print $1}')
    if [ $FILE_COUNT -ne 0 ]; then

        # Remove files from the list that have been removed by this commit
        touch $TMPDIR/reformatted-patches/$COMMIT/files-to-format
        for PFILE in $(cat $TMPDIR/reformatted-patches/$COMMIT/raw-files-to-format); do
            if [ ! -f $PFILE ]; then
                echo "Skipping removed file $PFILE from commit"
            else
                echo $PFILE >> $TMPDIR/reformatted-patches/$COMMIT/files-to-format
            fi
        done

        # Check our file count again to make sure we still have some files left to reformat
        FILE_COUNT=$(wc -l $TMPDIR/reformatted-patches/$COMMIT/files-to-format | awk '{print $1}')
        if [ $FILE_COUNT -ne 0 ]; then
            # And reformat them with clang
            clang-format-21 --style=file:./.clang-format -i --files=$TMPDIR/reformatted-patches/$COMMIT/files-to-format

            # stage each change to the commit here
            for PFILE in $(cat $TMPDIR/reformatted-patches/$COMMIT/files-to-format); do
                if [ -f $PFILE ]; then
                    git add $PFILE
                fi
            done

            # Commit the change
            git commit --amend --no-edit
        else
            echo "Skipping commit $COMMIT, no files to reformat"
        fi
    else
        echo "Skipping commit $COMMIT, no files to reformat"
    fi
    echo "Done with commit $COMMIT"
done

# Now build a reformatted rebase branch on the PRE TAG
git checkout -b $REBASE_BRANCH-reformat $PRE_FORMAT_TAG

# And for each reformatted commit, cherry pick it to this branch
for COMMIT in $(cat $TMPDIR/commits-to-reformat); do
    # Get the reformatted commit id
    REFORMATTED_COMMIT=$(git rev-parse ${COMMIT}-reformat)

    # Do the cherry pick
    git cherry-pick -X theirs $REFORMATTED_COMMIT
    if [ $? -ne 0 ]; then
        echo "Cherry pick failed, dropping to shell for resolution"
        echo "Resolve the cherry pick, and run git cherry-pick --continue"
        echo "When the cherry-pick is complete, exit this subshell"
        /bin/bash
    fi
done

# Now rebase the newly reformatted rebase branch on the POST TAG
git rebase -X theirs $PRE_FORMAT_TAG $REBASE_BRANCH-reformat --onto $POST_FORMAT_TAG

if [ $? -ne 0 ]; then
    echo "Rebase to post format tag has conflicts, please resolve"
    echo "And run git rebase --continune to complete the rebase process"
    echo "Exit this subshell when complete"
    /bin/bash
fi

# Now that we're done, lets do a final clang-reformat to make sure nothing too
# egregious has snuck into the branch
git diff --name-only $(git merge-base $POST_FORMAT_TAG $REBASE_BRANCH-reformat)..$REBASE_BRANCH-reformat \
    | grep -E ".*\.c$|.*\.h$|.*\.c\.in$|.*\.h\.in$" > $TMPDIR/raw-final-reformat-files 
for PFILE in $(cat $TMPDIR/raw-final-reformat-files); do
    if [ -f $PFILE ]; then
        echo $PFILE >> $TMPDIR/final-reformat-files
    fi
done
clang-format-21 --style=file:./.clang-format --files=$TMPDIR/final-reformat-files --verbose -i

git diff -u > ./final-reformat.patch
git reset --hard

# and inform the cleanup function that we've completed so the reformat branch is 
# preserved
ERROR_ENCOUNTERED=no
echo
echo "Reformat complete. You should now be checked out on a branch"
echo "Named ${REBASE_BRANCH}-reformat which contains your specified branch, reformatted"
echo "For our new coding style.  Please review this branch carefully for any errors"
echo "That may have occured during conversion"
FILE_LINES=$(wc -l ./final-reformat.patch | awk '{print $1}')
if [ $FILE_LINES -ne 0 ]; then
    echo
    echo "There are some changes that have been detected which we could not resovle, please"
    echo "Inspect the ./final-reformat.patch file to make the noted corrections by hand"
fi

exit 0
