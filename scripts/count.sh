#!/bin/bash

./scripts/allfiles.sh
cat `cat allfiles.txt` | wc -l
rm allfiles.txt