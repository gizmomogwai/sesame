#!/bin/bash
project=`basename $(pwd)`

INTERACTIVE=
if [ -z "$@" ]
then
       INTERACTIVE="--interactive --tty"
fi

podman run --rm $INTERACTIVE \
  -v$(pwd)/..:/ws \
  -v$HOME/Sync/configs/sesame:/root/.config/sesame \
  -v$HOME/Sync/configs/age:/root/.config/age \
  -v$(pwd)/linux-out:/ws/19-sesame/out localhost/ldc "$@"
