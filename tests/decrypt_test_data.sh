#!/usr/bin/env bash

PASSWORD="2zNAMFB6Xp9QG3giZuvTkI9Bifuswfdx"
FOLDER="test_data"

echo "Decrypting test data with aes-256-cbc"
openssl aes-256-cbc -d -out $FOLDER/spyeye_winxp.gz -in $FOLDER/spyeye_winxp.gz.enc -k $PASSWORD
openssl aes-256-cbc -d -out $FOLDER/teerac_winxp.gz -in $FOLDER/teerac_winxp.gz.enc -k $PASSWORD
openssl aes-256-cbc -d -out $FOLDER/zeus_winxp.gz -in $FOLDER/zeus_winxp.gz.enc -k $PASSWORD
echo "Done."

