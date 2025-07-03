#!/bin/sh

###################################################################
# Script to graph lock contention produced by REPORT_RWLOCK_CONTENTION
###################################################################
TEMPDIR=$(mktemp -d /tmp/contentiongraph.XXXXXX)
LOGFILE=$1
LABELS=$2

trap "rm -rf $TEMPDIR" EXIT

if [ ! -f $LOGFILE ]
then
    echo "No log file found" > /dev/stderr
    exit 1
fi
LOGFILEBASE=$(basename $LOGFILE)

mkdir -p $TEMPDIR/tids/

#
# Gather all our tids
#
declare -a filelines
declare -a sorted_lines

declare -a attimes
declare -a unblocktimes
declare -a levels

let offset=0

for i in $(cat $LOGFILE | grep "lock blocked" $LOGFILE | awk '{print $12}' | sort | uniq); do
    filelines=()
    sorted_lines=()
    mapfile -t filelines < <(cat $LOGFILE | grep "tid $i")
    IFS=$'\n' sorted_lines=($(sort -k 10 -n <<<"${filelines[*]}"))
    unset IFS

    attimes=()
    unblocktimes=()
    levels=()
    let up=$offset+1
    let down=$offset
    let firsttime=0
    echo "Processing tid $i"
    for LINE in "${sorted_lines[@]}"; do
        DURATION=$(echo $LINE | awk '{print $6}')
        ATTIME=$(echo $LINE | awk '{print $10}')
        UNBLOCKTIME=$(dc -e "$ATTIME $DURATION + p")
        if [ $firsttime -eq 0 ]; then
            let firsttime=$ATTIME
        fi
        ATTIME=$(dc -e"$ATTIME $firsttime - p")
        UNBLOCKTIME=$(dc -e "$UNBLOCKTIME $firsttime - p")
        attimes+=($ATTIME)
        levels+=($down)
        levels+=($up)
        unblocktimes+=($UNBLOCKTIME)
        levels+=($up)
        levels+=($down)
    done

#
# Write out our array to a file
#
    NUMELEMS=${#attimes[@]}
    for j in $(seq 0 1 $NUMELEMS); do
        let lvlidx=$j*4
        echo "${attimes[$j]} ${levels[$lvlidx]}" >> $TEMPDIR/tids/$i.data
        let lvlidx=$lvlidx+1
        echo "${attimes[$j]} ${levels[$lvlidx]}" >> $TEMPDIR/tids/$i.data
        let lvlidx=$lvlidx+1
        echo "${unblocktimes[$j]} ${levels[$lvlidx]}" >> $TEMPDIR/tids/$i.data
        let lvlidx=$lvlidx+1
        echo "${unblocktimes[$j]} ${levels[$lvlidx]}" >> $TEMPDIR/tids/$i.data
    done

    let offset=$offset+1
done

#
# Now lets use gnuplot to plot all the contentions
#

cat << EOF > $TEMPDIR/gnuplot.script
set term qt 
set format x '%.0f'
set xlabel "usecs"
set ylabel "contentions"
set yrange [0:5]
set xtics 1000000
EOF

echo -n "plot " >> $TEMPDIR/gnuplot.script

for i in $(ls $TEMPDIR/tids/*.data)
do
    TITLE=$(basename $i)
    echo -n "\"$i\" using 1:2 with lines title \"tid $TITLE\", " >> $TEMPDIR/gnuplot.script
    if [ -n "$LABELS" ]; then
        echo -n "\"$i\" using 1:2:1 with labels offset 0, char 1 notitle, " >> $TEMPDIR/gnuplot.script
    fi
done

echo "" >> $TEMPDIR/gnuplot.script
echo "pause -1" >> $TEMPDIR/gnuplot.script

gnuplot $TEMPDIR/gnuplot.script

