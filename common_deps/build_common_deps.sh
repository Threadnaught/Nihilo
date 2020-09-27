#!/bin/bash

#clean WAMR:
cd ${PWD}/wasm-micro-runtime
rm -rf product-mini/platforms/linux/build/
#recompile
cd product-mini/platforms/linux/
mkdir build
cd build
cmake ..
make