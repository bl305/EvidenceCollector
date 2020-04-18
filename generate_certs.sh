#!/bin/bash
openssl req -new -x509 -days 365 -nodes -out client.pem -keyout client.key
openssl req -new -x509 -days 365 -nodes -out server.pem -keyout server.key
