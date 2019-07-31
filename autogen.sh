#!/bin/sh

set -e

if [ "x$1" = "x-x" ] ; then
  set -x
  shift
fi

mkdir -p m4 && autoreconf --verbose --warning=all --install --force && echo "autoconfiguration done, to build: ./configure && make"
