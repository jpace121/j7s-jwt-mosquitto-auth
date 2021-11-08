#!/usr/bin/env bash
mosquitto_pub -u james -P test -h localhost -p 8081 -t test -m "test"
