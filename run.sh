#!/bin/sh
go run main.go & sleep 0.5 && ifconfig utun5 10.0.0.1 10.0.0.30 && tcpdump -i utun5 -n
