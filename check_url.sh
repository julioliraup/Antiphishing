#!/usr/bin/env bash
#
HTTP_STATUS=$(curl -o /dev/null -s -w "%{http_code}\n" $1)
if [ "$HTTP_STATUS" -eq 200 ]; then
  printf $1 | base64
fi
