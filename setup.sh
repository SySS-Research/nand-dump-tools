#!/bin/bash
script_dir=$(cd $(dirname $0); pwd -P)
cd ${script_dir}
virtualenv -p python3 .venv
. ./.venv/bin/activate
pip install -r requirements.txt
