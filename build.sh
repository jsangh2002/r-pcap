#!/bin/sh
rm *.o *.so
R CMD SHLIB pcap_parser.c
