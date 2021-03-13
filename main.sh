#!/usr/bin/env bash
base64 -w 0 small.png > testsmall.txt
base64 --decode testsmall.txt > output.pgn
