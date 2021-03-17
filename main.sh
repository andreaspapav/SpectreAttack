#!/usr/bin/env bash

TARGET=pixel.png
INPUT=input.txt
OUTPUT=output.txt

echo "Encoding image $TARGET to base64"
base64 -w 0 $TARGET > $INPUT
echo "Compiling Spectre variant 1 with _no_ optimizations"
gcc -O0 -o spectre spectre.c
./spectre input.txt output.txt
echo "Decoding the base64 string into output.png"
base64 --decode $OUTPUT > output.png 2>/dev/null
echo "Complete."
convert $TARGET output.png +append out.png
eog out.png

