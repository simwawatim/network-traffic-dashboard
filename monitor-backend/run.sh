#!/bin/bash
source env/bin/activate
uvicorn server:app --reload
