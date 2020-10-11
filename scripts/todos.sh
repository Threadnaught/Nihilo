#!/bin/bash

./scripts/allfiles.sh
cat `cat allfiles.txt` | grep TODO | wc -l
rm allfiles.txt