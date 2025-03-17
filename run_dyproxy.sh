#!/bin/bash

./venv/bin/gunicorn -w 1 --threads 1 main:app