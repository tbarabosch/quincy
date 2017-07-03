#!/usr/bin/env bash

PASSWORD="2zNAMFB6Xp9QG3giZuvTkI9Bifuswfdx"
FOLDER="test_data"

echo "Encrypting test data with aes-256-cbc"
openssl aes-256-cbc -in $FOLDER/spyeye_winxp.gz -out $FOLDER/spyeye_winxp.gz.enc -k $PASSWORD
openssl aes-256-cbc -in $FOLDER/teerac_winxp.gz -out $FOLDER/teerac_winxp.gz.enc -k $PASSWORD
openssl aes-256-cbc -in $FOLDER/zeus_winxp.gz -out $FOLDER/zeus_winxp.gz.enc -k $PASSWORD
echo "Done."
