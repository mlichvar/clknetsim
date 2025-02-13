# Copyright (C) 2010, 2011  Miroslav Lichvar <mlichvar@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

[ -n "$CLKNETSIM_TMPDIR" ] || CLKNETSIM_TMPDIR=tmp

client_pids=""

start_client() {
    local node=$1 client=$2 config=$3 suffix=$4 opts=$5
    local args=() line lastpid wrapper_options=""

    rm -f $CLKNETSIM_TMPDIR/log.$node $CLKNETSIM_TMPDIR/conf.$node

    [ $client = chrony ] && client=chronyd
    [ $client = ntp ] && client=ntpd

    if ! which $client$suffix &> /dev/null; then
	    echo "can't find $client$suffix in PATH"
	    return 1
    fi

    case $client in
	chronyd)
	    cat > $CLKNETSIM_TMPDIR/conf.$node <<-EOF
		pidfile $CLKNETSIM_TMPDIR/pidfile.$node
		allow
		cmdallow
		bindcmdaddress 0.0.0.0
		bindcmdaddress /clknetsim/unix/chronyd.sock
		$config
		EOF
	    args=(-d -f $CLKNETSIM_TMPDIR/conf.$node $opts)
	    ;;
	ntpd)
	    cat > $CLKNETSIM_TMPDIR/conf.$node <<-EOF
		pidfile $CLKNETSIM_TMPDIR/pidfile.$node
		restrict default
		$config
		EOF
	    args=(-n -c $CLKNETSIM_TMPDIR/conf.$node $opts)
	    ;;
	ptp4l)
	    cat > $CLKNETSIM_TMPDIR/conf.$node <<-EOF
		[global]
		$config
		EOF
	    args=(-f $CLKNETSIM_TMPDIR/conf.$node $opts)
	    ;;
	chronyc)
	    args=($opts -m)
	    while read line; do args+=("$line"); done <<< "$config"
	    ;;
	pmc)
	    args=($opts)
	    while read line; do args+=("$line"); done <<< "$config"
	    ;;
	ntpq)
	    while read line; do args+=(-c "$line"); done <<< "$config"
	    args+=($opts)
	    ;;
	sntp)
	    args=(-K /dev/null $opts $config)
	    ;;
	ntpdate)
	    args=($opts $config)
	    ;;
	busybox)
	    args=(ntpd -ddd -n)
	    while read line; do args+=(-p "$line"); done <<< "$config"
	    args+=($opts)
	    ;;
	phc2sys)
	    args=($opts $config)
	    ;;
	nsm)
	    args=($opts)
	    while read line; do args+=("$line"); done <<< "$config"
	    ;;
	*)
	    echo "unknown client $client"
	    exit 1
	    ;;
    esac

    unset LISTEN_FDS NOTIFY_SOCKET

    if [[ $CLKNETSIM_CLIENT_WRAPPER == *valgrind* ]]; then
	    wrapper_options="--log-file=$CLKNETSIM_TMPDIR/valgrind.$node --enable-debuginfod=no"
    fi

    LD_PRELOAD=${CLKNETSIM_PRELOAD:+$CLKNETSIM_PRELOAD:}$CLKNETSIM_PATH/clknetsim.so \
	CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=$CLKNETSIM_TMPDIR/sock \
	$CLKNETSIM_CLIENT_WRAPPER $wrapper_options \
	$client$suffix "${args[@]}" &> $CLKNETSIM_TMPDIR/log.$node &

    lastpid=$!
    disown $lastpid

    client_pids="$client_pids $lastpid"
}

start_server() {
    local nodes=$1 ret=0 wrapper_options="" i j
    shift

    if [[ $CLKNETSIM_SERVER_WRAPPER == *valgrind* ]]; then
	    wrapper_options="--log-file=$CLKNETSIM_TMPDIR/valgrind.0 --enable-debuginfod=no"
    fi

    $CLKNETSIM_SERVER_WRAPPER $wrapper_options \
	$CLKNETSIM_PATH/clknetsim "$@" -s $CLKNETSIM_TMPDIR/sock \
	$CLKNETSIM_TMPDIR/conf $nodes > $CLKNETSIM_TMPDIR/stats 2> $CLKNETSIM_TMPDIR/log

    if [ $? -ne 0 ]; then
        echo clknetsim failed 1>&2
        ret=1
    fi

    kill $client_pids &> /dev/null

    i=0
    for pid in $client_pids; do
	i=$[i + 1]
	j=0
	while kill -0 $pid &> /dev/null; do
	    j=$[j + 1]
	    if [ $j -gt 30 ]; then
		echo " node $i did not terminate" 1>&2
		ret=1
		break
	    fi
	    sleep 0.1
	done
    done

    client_pids=" "

    if ls $CLKNETSIM_TMPDIR/valgrind.* &> /dev/null; then
	if grep -q 'ERROR SUMMARY: [^0]' $CLKNETSIM_TMPDIR/valgrind.*; then
		echo " valgrind error" 1>&2
		ret=1
	fi
	sed -i '/^ERROR: ld.so: object.*from LD_PRELOAD cannot/d' $CLKNETSIM_TMPDIR/log.[0-9]*
    fi

    return $ret
}

generate_seq() {
    $CLKNETSIM_PATH/clknetsim -G "$@"
}

generate_config1() {
    local nodes=$1 offset=$2 freqexpr=$3 delayexprup=$4 delayexprdown=$5 refclockexpr=$6 i

    for i in `seq 2 $nodes`; do
	echo "node${i}_offset = $offset"
	echo "node${i}_freq = $freqexpr"
	echo "node${i}_delay1 = $delayexprup"
	if [ -n "$delayexprdown" ]; then
	    echo "node1_delay${i} = $delayexprdown"
	else
	    echo "node1_delay${i} = $delayexprup"
	fi
        [ -n "$refclockexpr" ] && echo "node${i}_refclock = $refclockexpr"
    done > $CLKNETSIM_TMPDIR/conf
}

generate_config2() {
    local nodes=$1 offset=$2 freqexpr=$3 delayexpr=$4 i j

    for i in `seq 2 $nodes`; do
	echo "node${i}_offset = $offset"
	echo "node${i}_freq = $freqexpr"
	for j in `seq 1 $nodes`; do
	    [ $i -eq $j ] && continue
	    echo "node${i}_delay${j} = $delayexpr"
	    echo "node${j}_delay${i} = $delayexpr"
	done
    done > $CLKNETSIM_TMPDIR/conf
}

generate_config3() {
    local topnodes=$1 nodes=$2 offset=$3 freqexpr=$4 delayexprup=$5 delayexprdown=$6 i j

    for i in `seq $[$topnodes + 1] $nodes`; do
	echo "node${i}_offset = $offset"
	echo "node${i}_freq = $freqexpr"
	for j in `seq 1 $topnodes`; do
	    [ $i -eq $j ] && continue
	    echo "node${i}_delay${j} = $delayexprup"
	    if [ -n "$delayexprdown" ]; then
		echo "node${j}_delay${i} = $delayexprdown"
	    else
		echo "node${j}_delay${i} = $delayexprup"
	    fi
	done
    done > $CLKNETSIM_TMPDIR/conf
}

generate_config4() {
    local stablenodes=$1 subnets=$2 offset=$3 freqexpr=$4 delayexpr=$5
    local subnet i j added

    echo "$subnets" | tr '|' '\n' | while read subnet; do
	for i in $subnet; do
	    if ! [[ " $stablenodes $added " =~ [^0-9]$i[^0-9] ]]; then
		echo "node${i}_offset = $offset"
		echo "node${i}_freq = $freqexpr"
	    fi
	    for j in $subnet; do
		[ $i -eq $j ] && continue
		echo "node${i}_delay${j} = $delayexpr"
	    done
	    added="$added $i"
	done
    done > $CLKNETSIM_TMPDIR/conf
}

find_sync() {
    local offlog=$1 freqlog=$2 index=$3 offsync=$4 freqsync=$5 smooth=$6

    [ -z "$smooth" ] && smooth=0.05

    paste <(cut -f $index $1) <(cut -f $index $2) | awk '
    BEGIN {
	lastnonsync = -1
	time = 0
    }
    {
	off = $1 < 0 ? -$1 : $1
	freq = $2 < 0 ? -$2 : $2

	if (avgoff == 0.0 && avgfreq == 0.0) {
	    avgoff = off
	    avgfreq = freq
	} else {
	    avgoff += '$smooth' * (off - avgoff)
	    avgfreq += '$smooth' * (freq - avgfreq)
	}

	if (avgoff > '$offsync' || avgfreq > '$freqsync') {
	    lastnonsync = time
	}
	time++
    } END {
	if (lastnonsync < time) {
	    print lastnonsync + 1
	} else {
	    print -1
	}
    }'
}

get_stat() {
    local statname=$1 index=$2

    if [ -z "$index" ]; then
	echo $(cat $CLKNETSIM_TMPDIR/stats | grep "^$statname:" | cut -f 2)
    else
	cat $CLKNETSIM_TMPDIR/stats | grep "^$statname:" | cut -f 2 |
	head -n $index | tail -n 1
    fi
}

check_stat() {
    local value=$1 min=$2 max=$3 tolerance=$4
    [ -z "$tolerance" ] && tolerance=0.0
    awk "
    BEGIN {
	eq = (\"$value\" == \"inf\" ||
	      $value + $value / 1e6 + $tolerance >= $min) &&
	     (\"$max\" == \"inf\" ||
	      (\"$value\" != \"inf\" &&
	      $value - $value / 1e6 - $tolerance <= $max))
	exit !eq
    }"
}

if [ -z "$CLKNETSIM_PATH" ]; then
    echo CLKNETSIM_PATH not set 2>&1
    exit 1
fi

if [ ! -x "$CLKNETSIM_PATH/clknetsim" -o ! -e "$CLKNETSIM_PATH/clknetsim.so" ]; then
    echo "can't find clknetsim or clknetsim.so in $CLKNETSIM_PATH"
    exit 1
fi

[ -d $CLKNETSIM_TMPDIR ] || mkdir $CLKNETSIM_TMPDIR
