#!/bin/bash

#
# Script requires `brew`
# - `/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
#
# Variables 
# - $IPA -> Source IPA
# - $MOBILEPROVISION -> Source embedded.mobileprovision
#                       find ~/Library/Developer/Xcode | grep embedded.mobileprovision
# - $TOOLS_DESTINATIONDIR -> Location where the tools will be installed (once)
# - $INJECTFRIDA -> Set to anything to inject Frida into the binary
#
IPA=/tmp/sample.ipa
MOBILEPROVISION=/tmp/sample/embedded.mobileprovision
TOOLS_DESTINATIONDIR=/tmp/iostools
INJECTFRIDA=y

IPA_DESTINATIONDIR=$(mktemp -d /tmp/IPA.XXX)
OUTFILE="resigned.ipa"
SIGNIDENTITY=`security find-identity -v -p codesigning | grep Developer | cut -d ' ' -f4`

###
# Preparing the tools environment
# - If the destination directory exists, this will be skipped!
###
if [ ! -d "$TOOLS_DESTINATIONDIR" ]; then
    if ! brew ls --versions node > /dev/null; then
        brew install node
    fi
    mkdir -p "${TOOLS_DESTINATIONDIR}"
    cd "${TOOLS_DESTINATIONDIR}"
    npm install applesign ios-deploy
    ln -s node_modules/.bin/applesign .
    ln -s node_modules/.bin/ios-deploy .
    curl -LO https://github.com/alexzielenski/optool/releases/download/0.1/optool.zip && unzip optool.zip
    curl -LO https://build.frida.re/frida/ios/lib/FridaGadget.dylib
fi

###
# Setting extra variables
###
OPTOOL=${TOOLS_DESTINATIONDIR}/optool
IOSDEPLOY=${TOOLS_DESTINATIONDIR}/ios-deploy
APPLESIGN=${TOOLS_DESTINATIONDIR}/applesign
FRIDA=${TOOLS_DESTINATIONDIR}/FridaGadget.dylib

###
# Extracting
###
cd "${IPA_DESTINATIONDIR}"
unzip "${IPA}"

###
# Injecting Frida
###
if [ -n "${INJECTFRIDA}" ]; then 
    cd Payload/*.app
    cp ${FRIDA} .
    EXECUTABLE=$(plutil -convert xml1 -o - Info.plist | xmllint --xpath 'string(/plist/dict/key[text()="CFBundleExecutable"]/following-sibling::string)' -)
    ${OPTOOL} install -c load -p "@executable_path/FridaGadget.dylib" -t "${EXECUTABLE}"
fi

###
# Repacking
###
cd ${IPA_DESTINATIONDIR}
zip -qr "${OUTFILE}" Payload

###
# Signing
###
${APPLESIGN} -r -i $SIGNIDENTITY -m "${MOBILEPROVISION}" "${OUTFILE}"

###
# If Frida is injected, it is required that we start the app with debugging.
# Otherwise we cannot connect to frida, since USB forwarding is not enabled.
###
if [ -n "${INJECTFRIDA}" ]; then 
    ###
    # We unpack once more, to allow debugging
    ###
    unzip -o "${OUTFILE}"

    ###
    # Deploying
    ###
    ${IOSDEPLOY} -L -W -b Payload/*.app
else
    ###
    # Deploying
    ###
    ${IOSDEPLOY} -W -b "${OUTFILE}"
fi