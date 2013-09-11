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

client_pids=""

start_client() {
    local node=$1 client=$2 config=$3 suffix=$4 opts=$5

    rm -f tmp/log.$node tmp/conf.$node

    case $client in
	chrony|chronyd)
	    cat > tmp/conf.$node <<-EOF
		pidfile tmp/pidfile.$node
		allow
		$config
		EOF
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper chronyd$suffix -d -f tmp/conf.$node $opts &> tmp/log.$node &
	    ;;
	ntp|ntpd)
	    cat > tmp/conf.$node <<-EOF
		pidfile tmp/pidfile.$node
		restrict default
		logconfig=syncstatus +allevents
		$config
		EOF
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper ntpd$suffix -n -c tmp/conf.$node $opts &> tmp/log.$node &
	    ;;
	ntpq)
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper ntpq$suffix -c 'rv 0' -c ass -c 'mrv 1 1' $config &> tmp/log.$node &
	    ;;
	ntpdate)
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper ntpdate$suffix $config &> tmp/log.$node &
            ;;
	busybox)
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper busybox$suffix ntpd -ddd -n -p $config &> tmp/log.$node &
	    ;;
	phc2sys)
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper phc2sys$suffix -s /dev/ptp0 -O 0 $config &> tmp/log.$node &
	    ;;
	ptp4l)
	    cat > tmp/conf.$node <<-EOF
		[global]
		$config
		EOF
	    LD_PRELOAD=$CLKNETSIM_PATH/clknetsim.so \
	    CLKNETSIM_NODE=$node CLKNETSIM_SOCKET=tmp/sock \
	    $client_wrapper ptp4l$suffix -f tmp/conf.$node $opts &> tmp/log.$node &
	    ;;
	*)
	    echo "unknown client $client"
	    exit 1
	    ;;
    esac
    client_pids="$client_pids $!"
}

start_server() {
    local nodes=$1 ret=0
    shift
    $server_wrapper $CLKNETSIM_PATH/clknetsim "$@" -s tmp/sock tmp/conf $nodes > tmp/stats 2> tmp/log
    if [ $? -ne 0 ]; then
        echo clknetsim failed 1>&2
        ret=1
    fi
    kill $client_pids &> /dev/null
    client_pids=" "
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
    done > tmp/conf
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
    done > tmp/conf
}

generate_config3() {
    local topnodes=$1 nodes=$2 offset=$3 freqexpr=$4 delayexpr=$5 i j

    for i in `seq $[$topnodes + 1] $nodes`; do
	echo "node${i}_offset = $offset"
	echo "node${i}_freq = $freqexpr"
	for j in `seq 1 $topnodes`; do
	    [ $i -eq $j ] && continue
	    echo "node${i}_delay${j} = $delayexpr"
	    echo "node${j}_delay${i} = $delayexpr"
	done
    done > tmp/conf
}

generate_config4() {
    local stablenode=$1 nodes=$2 offset=$3 freqexpr=$4 delayexpr=$5 i j

    for i in `seq 1 $nodes`; do
	if [ $i -ne $stablenode ]; then
	    echo "node${i}_offset = $offset"
	    echo "node${i}_freq = $freqexpr"
	fi
	for j in `seq 1 $nodes`; do
	    [ $i -eq $j ] && continue
	    echo "node${i}_delay${j} = $delayexpr"
	done
    done > tmp/conf
}

find_sync() {
    local offlog=$1 freqlog=$2 index=$3 offsync=$4 freqsync=$5 smooth=$6

    [ -z "$smooth" ] && smooth=0.05

    paste <(cut -f $index $1) <(cut -f $index $2) | awk '
    {
	time++
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
    } END {
	if (lastnonsync < time) {
	    print lastnonsync
	} else {
	    print -1
	}
    }'
}

get_stat() {
    local statname=$1 index=$2

    if [ -z "$index" ]; then
	echo $(cat tmp/stats | grep "^$statname:" | cut -f 2)
    else
	cat tmp/stats | grep "^$statname:" | cut -f 2 |
	head -n $index | tail -n 1
    fi
}

check_stat() {
    local value=$1 min=$2 max=$3
    awk "BEGIN { exit !($value >= $min && $value <= $max) }"
}

if [ -z "$CLKNETSIM_PATH" ]; then
    echo CLKNETSIM_PATH not set 2>&1
    exit 1
fi

if [ ! -x "$CLKNETSIM_PATH/clknetsim" -o ! -e "$CLKNETSIM_PATH/clknetsim.so" ]; then
    echo "can't find clknetsim or clknetsim.so in $CLKNETSIM_PATH"
    exit 1
fi

[ -d tmp ] || mkdir tmp
