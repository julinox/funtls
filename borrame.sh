#!/bin/bash

#1603030050
echo "bd96f01576de0df95135f06ef9b604909430fab5a7a36fafcc1734829906b9dfeb961ee420897cd05b741cfa72ac51fcf7570bedc00e1c0798dd36140a681c2356f744dd06c25c771f8c8a405f9de2c2" | xxd -r -p > finished.enc
openssl enc -d -aes-256-cbc -in finished.enc -K 9551dec2fe56c598cea74767b5543f7e28b86578f2287b0f73dde2323c45dbe4 -iv 211574edae7af5716d21e8b1cbab2c02 -nopad | xxd -p

