### Application

- IPA version:
    + Omed: https://github.com/theart42/omed.ios

-  Source version:
    + https://github.com/theart42/hack.lu/blob/master/IOS/Omed.ipa


### Codesigning
- Free account - requires AppleID

#### HelloWorld

- Create a new HelloWorld program in XCode and build it. This will give you the embedded.mobileprovision for resigning.
- See `HelloWorldCodeSign.png`

#### Resign application

- Requires embedded.mobileprovision, as created for HelloWorld.
    + Find it like this: `find ~/Library/Developer/Xcode | grep embedded.mobileprovision`

- Requires brew: https://brew.sh/index_nl.html

- Specify the IPA
- Specify the MobileProvision
- Specify the location where the tools should be installed.
- The certificate must be trusted (Settings -> General -> Profiles)
    + If the certificate is not trusted: `error: process launch failed: Security`

```shell
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
```


#### Everybody happy?

- Did the resigning process work for you?
- Is the application running?
- Can you connect Frida; `frida -U gadget` 
- Does the script below work inside Frida?

```javascript
// https://www.frida.re/docs/examples/ios/

// Defining a Block that will be passed as handler parameter to +[UIAlertAction actionWithTitle:style:handler:]
var handler = new ObjC.Block({
  retType: 'void',
  argTypes: ['object'],
  implementation: function () {
  }
});

// Import ObjC classes
var UIAlertController = ObjC.classes.UIAlertController;
var UIAlertAction = ObjC.classes.UIAlertAction;
var UIApplication = ObjC.classes.UIApplication;

// Using Grand Central Dispatch to pass messages (invoke methods) in application's main thread
ObjC.schedule(ObjC.mainQueue, function () {
  // Using integer numerals for preferredStyle which is of type enum UIAlertControllerStyle
  var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_('Frida', 'Hello from Frida', 1);
  // Again using integer numeral for style parameter that is enum
  var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
  alert.addAction_(defaultAction);
  // Instead of using `ObjC.choose()` and looking for UIViewController instances
  // on the heap, we have direct access through UIApplication:
  UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
})
```

### (EXTRA) Inspecting embedded.mobileprovision

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


