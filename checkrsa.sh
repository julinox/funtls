#!/bin/bash

encrypted=""
decrypted=""

fileData="data.bin"
fileDataDecrypt="datadecrypted.bin"
fileOpensslDecrypt="openssldecrypt.bin"

echo "$encrypted" | xxd -r -p > "$fileData"
echo "$decrypted" | xxd -r -p > "$fileDataDecrypt"
openssl pkeyutl -decrypt -inkey certs/server.key -in data.bin -out "$fileOpensslDecrypt"


# Comparar los archivos binarios
if cmp -s "$fileDataDecrypt" "$fileOpensslDecrypt"; then
    echo "Match at decryption"
else
    echo "Error. No match!"
fi

rm "$fileData" "$fileDataDecrypt" "$fileOpensslDecrypt"