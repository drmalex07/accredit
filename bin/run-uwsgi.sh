#!/bin/bash



PIDFILE=/tmp/uwsgi-accredit.pid

case "$1" in

start)
    echo 'Starting uWSGI ...'
    uwsgi --ini-paste-logged development.ini --pidfile ${PIDFILE}
    rm -v ${PIDFILE}
    ;;
restart)
    echo 'Restarting uWSGI by pid ...'
    if test -f ${PIDFILE}
    then
        uwsgi --reload ${PIDFILE}
    fi
    ;;
stop)
    echo 'Stopping uWSGI by pid ...'
    if test -f ${PIDFILE}
    then
        uwsgi --stop ${PIDFILE}
    fi
    ;;
*)
    echo ' ** Unknown command **'
    ;;
esac
