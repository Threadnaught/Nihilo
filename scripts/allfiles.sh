#!/bin/bash

find . -not -path ./common_deps/\* | grep \\.[ch] > allfiles.txt
find . -not -path ./common_deps/\* | grep \\.yaml >> allfiles.txt
find . -not -path ./common_deps/\* | grep Dockerfile >> allfiles.txt
find . -not -path ./common_deps/\* | grep \\.json >> allfiles.txt