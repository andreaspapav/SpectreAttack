#!/usr/bin/env bash
base64 -w 0 pixel.png > input.txt
gcc -o spectre spectre.c
./spectre
base64 --decode output.txt > output.png

