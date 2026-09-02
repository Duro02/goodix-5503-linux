#!/bin/sh
[ "$1" = post ] && systemctl restart fprintd.service
exit 0
