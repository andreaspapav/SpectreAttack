#!/usr/bin/env bash
echo "encoding image from input.png..."
base64 -w 0 small.png > input.txt
echo "compiling.."
gcc -o spectre spectre.c
./spectre
echo "saving output to output.png..."
base64 --decode output.txt > output.png
echo "Complete."
convert small.png output.png +append out.png
eog out.png

