#!/bin/bash

CURLRC=~/testcase_curlrc

# Set up the routing needed for the simulation
/setup.sh

# The following variables are available for use:
# - ROLE contains the role of this execution context, client or server
# - SERVER_PARAMS contains user-supplied command line parameters
# - CLIENT_PARAMS contains user-supplied command line parameters

generate_outputs_http3() {
    for i in $REQUESTS
    do
        OUTFILE=$(basename $i)
        echo -e "--http3-only\n-o /downloads/$OUTFILE\n--url $i" >> $CURLRC
        echo "--next" >> $CURLRC
    done
    # Remove the last --next
    head -n -1 $CURLRC > $CURLRC.tmp
    mv $CURLRC.tmp $CURLRC 
}

dump_curlrc() {
    echo "Using curlrc:"
    cat $CURLRC
}

# Helper function to wait for a reap child processes as they complete
declare -A pidstarttimes 
declare -A pidfiles
let REQHANDLED=0
let REQINFLIGHT=0
wait_for_client_completion() {
       local hostname=$1
       local hostport=$2
       while true
       do
           wait -n -p PIDNAME
           EXITCODE=$?
           if [ $EXITCODE -eq 127 ]
           then
            if [ $REQHANDLED -eq 0 ]
            then
                echo "All processes done"
            fi
            break
           fi
           if [[ ! -n "${pidstarttimes["$PIDNAME"]}" ]]
           then
                echo "pid $PIDNAME never started, skipping"
                continue
           fi
           ENDTIME=$(date +%s)
           let DURATION=$ENDTIME-${pidstarttimes["$PIDNAME"]}
           echo "Finish client for ${pidfiles["$PIDNAME"]} with code $EXITCODE at $ENDTIME, DURATION $DURATION"
           if [ $EXITCODE -ne 0 ]
           then
                local OUTFILE=${pidfiles["$PIDNAME"]}
                echo "Restarting request for ${pidfiles["$PIDNAME"]}"
                SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs quic-hq-interop $hostname $hostport ./jobreq/$OUTFILE.txt &
                NEWPID=$!
                echo "Start client for $OUTFILE (PID $NEWPID, KESEQ $KEYSEQ) at $STARTTIME"
                pidstarttimes["$NEWPID"]=$STARTTIME
                pidfiles["$NEWPID"]=$OUTFILE
           else 
                let REQINFLIGHT=$REQINFLIGHT-1
                if [ $REQHANDLED -eq 0 ]
                then
                    continue
                fi
                break
           fi
       done
}

if [ "$ROLE" == "client" ]; then
    # Wait for the simulator to start up.
    echo "Waiting for simulator"
    /wait-for-it.sh sim:57832 -s -t 30
    echo "TESTCASE is $TESTCASE"
    rm -f $CURLRC 

    case "$TESTCASE" in
    "http3")
        echo -e "--verbose\n--parallel" >> $CURLRC
        generate_outputs_http3
        dump_curlrc
        SSL_CERT_FILE=/certs/ca.pem curl --config $CURLRC || exit 1
        exit 0
        ;;
    "handshake"|"transfer"|"retry"|"ipv6")
        HOSTNAME=none
        for req in $REQUESTS
        do
            OUTFILE=$(basename $req)
            if [ "$HOSTNAME" == "none" ]
            then
                HOSTNAME=$(printf "%s\n" "$req" | sed -ne 's,^https://\([^/:]*\).*,\1,p')
                HOSTPORT=$(printf "%s\n" "$req" | sed -ne 's,^https://[^:/]*:\([^/]*\).*,\1,p')
            fi
            echo -n "$OUTFILE " >> ./reqfile.txt
        done
        SSLKEYLOGFILE=/logs/keys.log SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs quic-hq-interop $HOSTNAME $HOSTPORT ./reqfile.txt || exit 1
        exit 0
        ;;
    "multiconnect")
       HOSTNAME=none
       mkdir ./jobreq
       let KEYSEQ=0
       REQHANDLED=$(echo $REQUESTS | wc -w)
       for req in $REQUESTS
       do
           OUTFILE=$(basename $req)
           if [ "$HOSTNAME" == "none" ]
           then
               HOSTNAME=$(printf "%s\n" "$req" | sed -ne 's,^https://\([^/:]*\).*,\1,p')
               HOSTPORT=$(printf "%s\n" "$req" | sed -ne 's,^https://[^:/]*:\([^/]*\).*,\1,p')
           fi
           echo -n "$OUTFILE " > jobreq/$OUTFILE.txt
           STARTTIME=$(date +%s)
           SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs quic-hq-interop $HOSTNAME $HOSTPORT ./jobreq/$OUTFILE.txt &
           NEWPID=$!
           echo "Start client for $OUTFILE (PID $NEWPID, KESEQ $KEYSEQ) at $STARTTIME"
           pidstarttimes["$NEWPID"]=$STARTTIME
           pidfiles["$NEWPID"]=$OUTFILE
           let REQINFLIGHT=$REQINFLIGHT+1
           let KEYSEQ=$KEYSEQ+1
           let REQHANDLED=$REQHANDLED-1
           if [ $REQINFLIGHT -ge 5 ]
           then
            echo "Max connections reached, waiting for completion"
            wait_for_client_completion $HOSTNAME $HOSTPORT
           fi
       done
       echo "Finish up waiting"
       wait_for_client_completion $HOSTNAME $HOSTPORT
       # Don't record any key log here as its hard to co-ordinate multiple process, just use the server log
       rm -f /logs/keys.log
       exit 0
       ;; 
    "resumption")
        for req in $REQUESTS
        do
            OUTFILE=$(basename $req)
            echo -n "$OUTFILE " > ./reqfile.txt
            HOSTNAME=$(printf "%s\n" "$req" | sed -ne 's,^https://\([^/:]*\).*,\1,p')
            HOSTPORT=$(printf "%s\n" "$req" | sed -ne 's,^https://[^:/]*:\([^/]*\).*,\1,p')
            SSL_SESSION_FILE=./session.db SSLKEYLOGFILE=/logs/keys.log SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs quic-hq-interop $HOSTNAME $HOSTPORT ./reqfile.txt || exit 1
        done
        exit 0
        ;;
    "chacha20")
        for req in $REQUESTS
        do
            OUTFILE=$(basename $req)
            printf "%s " "$OUTFILE" >> ./reqfile.txt
            HOSTNAME=$(printf "%s\n" "$req" | sed -ne 's,^https://\([^/:]*\).*,\1,p')
            HOSTPORT=$(printf "%s\n" "$req" | sed -ne 's,^https://[^:/]*:\([^/]*\).*,\1,p')
        done
        SSL_CIPHER_SUITES=TLS_CHACHA20_POLY1305_SHA256 SSL_SESSION_FILE=./session.db SSLKEYLOGFILE=/logs/keys.log SSL_CERT_FILE=/certs/ca.pem SSL_CERT_DIR=/certs quic-hq-interop $HOSTNAME $HOSTPORT ./reqfile.txt || exit 1
        exit 0
        ;;
    *)
        echo "UNSUPPORTED TESTCASE $TESTCASE"
        exit 127
        ;;
    esac
elif [ "$ROLE" == "server" ]; then
    echo "TESTCASE is $TESTCASE"
    rm -f $CURLRC 
    case "$TESTCASE" in
    "handshake"|"transfer"|"ipv6")
        NO_ADDR_VALIDATE=yes SSLKEYLOGFILE=/logs/keys.log FILEPREFIX=/www quic-hq-interop-server 443 /certs/cert.pem /certs/priv.key
        ;;
    "multiconnect")
        MULTITHREAD=yes NO_ADDR_VALIDATE=yes SSLKEYLOGFILE=/logs/keys.log FILEPREFIX=/www quic-hq-interop-server 443 /certs/cert.pem /certs/priv.key
        ;;
    "retry"|"resumption")
     	NO_ADDR_VALIDATE=yes SSLKEYLOGFILE=/logs/keys.log FILEPREFIX=/www quic-hq-interop-server 443 /certs/cert.pem /certs/priv.key
        ;;
    "http3")
        FILEPREFIX=/www/ SSLKEYLOGFILE=/logs/keys.log ossl-nghttp3-demo-server 443 /certs/cert.pem /certs/priv.key
        ;;
    "chacha20")
        SSL_CIPHER_SUITES=TLS_CHACHA20_POLY1305_SHA256 SSLKEYLOGFILE=/logs/keys.log FILEPREFIX=/www quic-hq-interop-server 443 /certs/cert.pem /certs/priv.key
        ;;
    *)
        echo "UNSUPPORTED TESTCASE $TESTCASE"
        exit 127
        ;;
    esac
else
    echo "Unknown ROLE $ROLE"
    exit 127
fi

