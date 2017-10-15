### Codesigning


### TODO

- Free account - requires AppleID
- Requires embedded.mobileprovision
- Resign an application

```shell
OUTFILE="resigned.ipa"
INSERT_DYLIB="/Users/frank/IOS/Tools/insert_dylib"
IOSDEPLOY="ios-deploy"
APPLESIGN="/Users/frank/IOS/Tools/appmon/ipa_installer/node-applesign/bin/ipa-resign.js"
SIGNIDENTITY=`security find-identity -v -p codesigning | grep Developer | cut -d ' ' -f4`
DST=$(mktemp -d /tmp/IPA.XXX)

cd "${DST}"
unzip "${IPA}"
zip -qr "${OUTFILE}" Payload

${APPLESIGN} -r -i $SIGNIDENTITY -m "${MOBILEPROVISION}" "${OUTFILE}"
${IOSDEPLOY} -b "${OUTFILE}"
```


# Read mobile provision
```shell
MOBILEPROVISION=./embedded.mobileprovision
```


```shell
security cms -D -i "${MOBILEPROVISION}"
```

- Read its certificate

```shell
security cms -D -i "${MOBILEPROVISION}" | xmllint --xpath '/plist/dict/array/data/text()' - | base64 -D | openssl x509 -inform DER -noout -text
```

- Find device UDID the profile is provisioned for:

```shell
security cms -D -i "${MOBILEPROVISION}" | xmllint --xpath '/plist/dict/key[text()="ProvisionedDevices"]/following-sibling::array/string/text()' -
```

- Show the expiration date of the profile

```shell
security cms -D -i "${MOBILEPROVISION}" | xmllint --xpath '/plist/dict/key[text()="ExpirationDate"]/following-sibling::date/text()' -
```