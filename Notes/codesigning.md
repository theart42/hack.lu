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