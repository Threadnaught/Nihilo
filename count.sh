#!/bin/bash

find . -not -path ./common_deps/\* | grep \\.[ch] > allfiles.txt
cat `cat allfiles.txt` | wc -l
rm allfiles.txt