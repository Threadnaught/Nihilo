#!/bin/bash

mkdir -p Nih
cd Nih

#ensure docker is installed:
if ! command -v docker &> /dev/null; then
	echo "Docker must be installed"
	exit 1
fi

#ensure user is in docker group:
if ! id -nG "$USER" | grep -qw docker; then
	echo "User must be in docker group: sudo usermod -aG docker \$USER"
	echo "AND LOG OUT AND BACK IN!!!"
	exit 1
fi

git clone https://github.com/Threadnaught/Nihilo.git --recursive
echo "FROM ubuntu
RUN ln -snf \/usr\/share\/zoneinfo\/Europe\/Dublin \/etc\/localtime && echo Europe\/Dublin > \/etc\/timezone && \\
	apt update && apt install libleveldb-dev libmbedtls-dev libcjson-dev build-essential git wget tar cmake nano libmicrohttpd-dev -y  && \\
	wget https:\/\/github.com\/WebAssembly\/wasi-sdk\/releases\/download\/wasi-sdk-11\/wasi-sdk-11.0-linux.tar.gz && \\
	tar xvf wasi-sdk-11.0-linux.tar.gz && \\
	mv wasi-sdk-11.0 \/opt\/wasi-sdk && \\
	rm -rf wasi-sdk-11.0 wasi-sdk-11.0-linux.tar.gz" > Dockerfile

docker build . -t nihdock

docker run -v $PWD/Nihilo/:/nih/ nihdock bash -c "cd \/nih\/common_deps\/wasm-micro-runtime\/product-mini\/platforms\/linux\/; mkdir build; cd build; cmake ..; make; cd \/nih\/; mkdir /nih/bin; make"

echo "docker run -v $PWD/Nihilo/:/nih/ -it nihdock bash" > ./enter.sh

chmod +x enter.sh


