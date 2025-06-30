#!/bin/bash
source env/bin/activate
python3 test.py &   
uvicorn server:app --reload
