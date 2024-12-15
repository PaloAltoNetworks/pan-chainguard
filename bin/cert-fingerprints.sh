#!/bin/sh

usage() {
    echo "usage: $(basename $0) cert-directory"
    exit 1
}

# Usage: fingerprints directory
fingerprints() {
    dir=$1

    echo '"type","sha256"'
    for file in $(ls $dir/*.cer); do
	fp=$(openssl x509 -noout -fingerprint -sha256 -in $file)
	fp=$(echo $fp | sed -e 's/.*=//')
	fp=$(echo $fp | sed -e 's/://g')
	echo \"root\",\"$fp\"
    done
}

if [ $# != 1 ] || [ $1 = '--help' ]; then
    usage
fi
if [ ! -d $1 ]; then
    echo "$1: not directory"
    exit 1
fi

fingerprints $1
