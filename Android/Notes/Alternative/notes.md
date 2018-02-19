### Injecting Frida

- We will extract the APK and insert the Frida library
- The directory `lib/` will need the correct architecture directory. For the emulator this is `x86`. Reference: https://developer.android.com/ndk/guides/abis.html

```bash
apktool d app-release.apk
cd app-release/lib/
# Create all ABI directories
mkdir -p {armeabi,armeabi-v7a,arm64-v8a,x86,x86_64,mips,mips64}
# For now we will use the x86 ABI
cd x86
wget https://github.com/frida/frida/releases/download/10.6.11/frida-gadget-10.6.11-android-x86.so.xz
xz -d frida-gadget-10.6.11-android-x86.so.xz
```

- For an Android device, get the correct `frida-gadget-10.6.11-android-<ARCHITECTURE>.so.xz` in the right directory.

- Library rename. Android expects `lib<NAME>.so`

```
mv frida-gadget-10.6.11-android-x86.so libfrida.so
cd ../../
```

- Modify Smali to include frida, when loading. Find the starting action.

```
cat AndroidManifest.xml | grep activity | grep 'android:name'
```

__Output__
```xml
 <activity android:configChanges="keyboardHidden|orientation" android:label="@string/app_name" android:name="nl.secureapps.demohacklu.MainActivity" android:screenOrientation="portrait" android:theme="@style/AppTheme.NoActionBar">
```

- Check out the `MainActivity` in `jadx-gui`
- This is the entrypoint for the application
- Navigate to original `app-release.apk`

```
jadx-gui app-release.apk
```

__MainActivity.onCreate__
```java
protected void onCreate(Bundle savedInstanceState) {
    StrictMode.setThreadPolicy(new Builder().permitAll().build());
    super.onCreate(savedInstanceState);
    context = getApplicationContext();
    setContentView((int) R.layout.activity_main);
    setSupportActionBar((Toolbar) findViewById(R.id.toolbar));
    LocalBroadcastManager.getInstance(this).registerReceiver(this.broadcastReceiver, new IntentFilter(OUTPUT_EVENT));
    Hide hidePw = new Hide();
}
```

- Lets check it out in Smali

__app-release/smali/nl/secureapps/demohacklu/MainActivity.smali__
```smali
# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 7
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    .line 46
    new-instance v3, Landroid/os/StrictMode$ThreadPolicy$Builder;

    invoke-direct {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>()V

    invoke-virtual {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;->permitAll()Landroid/os/StrictMode$ThreadPolicy$Builder;
```

- Define a string with the name of our library. Note that we should not include `lib` or the extension `.so`
- Next make a call to load the library

__app-release/smali/nl/secureapps/demohacklu/MainActivity.smali__
```smali
# virtual methods
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 7
    .param p1, "savedInstanceState"    # Landroid/os/Bundle;

    .prologue
    .line 46

    const-string v0, "frida"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    new-instance v3, Landroid/os/StrictMode$ThreadPolicy$Builder;

    invoke-direct {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;-><init>()V

    invoke-virtual {v3}, Landroid/os/StrictMode$ThreadPolicy$Builder;->permitAll()Landroid/os/StrictMode$ThreadPolicy$Builder;
```

- We might need `Internet` permissions for Frida to be able to communicate!
- This is supervised by `AndroidManifest.xml`
- In this case we already have the permission `<uses-permission android:name="android.permission.INTERNET"/>`

```xml
<?xml version="1.0" encoding="utf-8" standalone="no"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="nl.secureapps.demohacklu" platformBuildVersionCode="25" platformBuildVersionName="7.1.1">
    <uses-permission android:name="android.permission.INTERNET"/>
    <meta-data android:name="android.support.VERSION" android:value="25.3.1"/>
    <application android:allowBackup="true" android:icon="@mipmap/ic_launcher" android:label="@string/app_name" android:roundIcon="@mipmap/ic_launcher_round" android:supportsRtl="true" android:theme="@style/AppTheme">
        <activity android:configChanges="keyboardHidden|orientation" android:label="@string/app_name" android:name="nl.secureapps.demohacklu.MainActivity" android:screenOrientation="portrait" android:theme="@style/AppTheme.NoActionBar">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

- We can now repackage the APK

```bash
NEWAPK=app-release-frida.apk
apktool b app-release -o ${NEWAPK}
```

__Output__

```
I: Using Apktool 2.3.1
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Copying libs... (/lib)
I: Building apk file...
I: Copying unknown files/dir...
```

- We have a new APK. Now we need to resign it!
- Create a keystore (this keystore can be reused for repackaging other applications)

```bash
KEYSTORE=custom-keystore
KEYSTORE_ALIAS=custom-alias

keytool -genkey -v -keystore ${KEYSTORE} -alias ${KEYSTORE_ALIAS} -keyalg RSA -keysize 2048 -validity 1000
```

__Interactive__
```
Enter keystore password:
Re-enter new password:
What is your first and last name?
  [Unknown]:
What is the name of your organizational unit?
  [Unknown]:
What is the name of your organization?
  [Unknown]:
What is the name of your City or Locality?
  [Unknown]:
What is the name of your State or Province?
  [Unknown]:
What is the two-letter country code for this unit?
  [Unknown]:
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
  [no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 1,000 days
    for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
Enter key password for <custom-alias>
    (RETURN if same as keystore password):
Re-enter new password:
[Storing custom-keystore]
```

- We now have a keystore. We can sign the new APK with this keystore

```
jarsigner -sigalg SHA1withRSA -digestalg SHA1 -keystore ${KEYSTORE} ${NEWAPK} ${KEYSTORE_ALIAS}
```

__Output__:

```
Enter Passphrase for keystore:
jar signed.

Warning:
No -tsa or -tsacert is provided and this jar is not timestamped. Without a timestamp, users may not be able to validate this jar after the signer certificate's expiration date (2020-11-12) or after any future revocation date.
```

- We have now repackaged the APK and inserted the Frida gadget

### Install

- We can install the APK using `adb`. We first need to uninstall the previous version, which can also be done by using `adb`
- We need to know the package name first. Check the AndroidManifest.xml.

```
cat app-release/AndroidManifest.xml | grep -oE 'package=".*?"'
```

__Output__
```
package="nl.secureapps.demohacklu"
```

- Lets uninstall the old version

```
adb shell pm uninstall nl.secureapps.demohacklu
```

__Output__

```
Success
```

- (_Optional_) If you need to get an existing APK from the system use something like this. The command below will grab _all_ packages.
```
mkdir extract_all
cd extract_all
adb shell pm list packages | sed 's/^package://g' | xargs -L1 adb shell pm path | sed 's/^package://g' | xargs -L1 adb pull
```

- Now we can reinstall our own version

```bash
adb install ${NEWAPK}
```

- Start the application from the Emulator/Device. It should now wait for a connection from Frida client. It will therefore show an empty screen when loading.

### Attaching Frida

- In case of the emulator we need to forward the Frida port.

```
adb forward tcp:27042 tcp:27042
```

- We should now be able to connect. We need to specify the application as `gadget`

__Emulator__
```
frida -H 127.0.0.1 gadget
```

__Device over USB__
```
frida -U gadget
```

__Output (similar)__
```
     ____
    / _  |   Frida 10.6.52 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/

[Remote::gadget]->
```

- We can check if it works:

```
[Remote::gadget]-> console.log('hello world')
hello world
undefined
[Remote::gadget]->
```

- Notice that Javascript will always return with the return value of the called procedure; in this case `undefined`

- An example with an anonymous function:
```
[Remote::gadget]-> (function() { console.log('Hello World'); return 'Return Value'})()
Hello World
"Return Value"
[Remote::gadget]->
```

### What can we do with Frida?

- Frida is able to communicate with the Java environment as well as with any other libraries
- Frida is able to intercept and overwrite any function calls
- For now we want to interact with Java environment
- To tell Frida to interact with the Java environment the following is required

```javascript
function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            console.log('Hello World')
        }
    )}
}
// Call the function
myfunction()
```

- That didn't really interact, since there where no Java specifics called
- Lets create a Java `java.lang.String` object

```javascript
function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            // https://www.frida.re/docs/javascript-api/#java 
            // Dynamically get a JavaScript wrapper for className that you can instantiate objects from by calling $new() on it to invoke a constructor.
            const JavaString = Java.use('java.lang.String');
            // Create an instance of java.lang.String and assign it to a variable 
            var exampleString1 = JavaString.$new('Hello World, this is an example string in Java.');
            console.log('[+] exampleString1: ' + exampleString1);
            console.log('[+] exampleString1.length(): ' + exampleString1.length());
        }
    )}
}
// Call the function
myfunction()
```

- Java supports function overloading. Frida is able to also use this. The `java.lang.String` constructor can be overloaded. Checkout https://docs.oracle.com/javase/7/docs/api/java/lang/String.html
- Lets create `java.lang.String` from some bytes and a 'java.nio.charset.Charset': `String(byte[] bytes, Charset charset)`

```javascript
function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            const JavaString = Java.use('java.lang.String');
            const Charset = Java.use('java.nio.charset.Charset');
            
            // We will get the default charset. 
            var charset = Charset.defaultCharset()

            // Create a byte array from a Javascript string
            const charArray = "This is a javascript string converted to a byte array".split('').map(function(c) {
                return c.charCodeAt(0)
            })
            // Create an instance of java.lang.String and assign it to a variable. Notice we use overload and call to specify the overloaded type and its arguments.
            exampleString2 = JavaString.$new.overload('[B', 'java.nio.charset.Charset').call(JavaString, charArray, charset)
            console.log('[+] exampleString2: ' + exampleString2);
            console.log('[+] exampleString2.length(): ' + exampleString2.length());
        }
    )}
}
// Call the function
myfunction()
```

- How can you find the overloads for a function? How we can we check the methods a class has? I have created some helper functions to do this

```javascript
function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            const JavaString = Java.use('java.lang.String');
            // Show all the properties of this class
            console.log('[+] Show object: ' + JSON.stringify(showObject(JavaString.$new.overloads), null ,4))
            // Show all overloads for the constructor
            console.log('[+] Constructor overloads: ' +getOverloads(JavaString.$new.overloads));
        }
    )}
}



// Emumerate all properties of an object.
function showObject(obj) {
    var result = null
    if (obj && obj.constructor === Array) {
        result = []
    } else if (obj === null) {
        return null
    } else {
        result = {}
    }
    for (property in obj) {
        if (obj.hasOwnProperty(property)) {
            var value = obj[property]
            if (typeof(value) === 'object' || typeof(value) === 'function') {
                if (obj.constructor === Array) {
                    result.push(showObject(value))
                } else {
                    result[property] = showObject(value)
                }
            } else {
                result[property] = value
            }
        }
    }
    return result
}

// Give this function the overloads array and it will return their signature.
function getOverloads(overloads) {
    var results = []
    for (i in overloads) {
        if (overloads[i].hasOwnProperty('argumentTypes')) {
            var parameters = []
            for (j in overloads[i].argumentTypes) {
                parameters.push("'" + overloads[i].argumentTypes[j].className + "'")
            }
        }
        // results.push(overloads[i].name + '(' + parameters.join(', ') + ')')
        results.push('.overload(' + parameters.join(', ') + ')')
    }
    return results.join('\n')
}
// Call the function
myfunction()
```

- Lets try to overwrite some application functionality.
- `StringBuilder`'s are very common in applications

```javascript
function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            const StringBuilder = Java.use('java.lang.StringBuilder');
            //Remember we used $new to invoke the constructor?
            //Now we need to overwrite $init instead of $new, since $new actually consists of allocate and init. We only want to overwrite the initialisation.
            //The code below will intercept String(byte[] bytes) constructor calls.
            StringBuilder.$init.overload('java.lang.String').implementation = function (str) {
                if (str !== null) {
                    // Only display 10 characters .. no spoilers ;)
                    console.log('new StringBuilder(' + str.replace("\n", "").slice(0,10) + '...);')   
                }
                return this.$init(str)
            }
            // The code below will intercept String.toString() calls.
            StringBuilder.toString.implementation = function () {   
                res = this.toString()
                if (res !== null) {
                    // Only display 10 characters .. no spoilers ;)
                    console.log('new StringBuilder.toString() => ' + res.replace("\n", "").slice(0,10) + '....')    
                }
                return res
            }

            console.log('[+] StringBuilder hooked - click around in the application')

        }
    )}
}
// Call the function
myfunction()
```

__Output__
```
new StringBuilder.toString() => Calling ht....
new StringBuilder.toString() => Text 51....
new StringBuilder.toString() => Text 52....
new StringBuilder.toString() => Text 53....
new StringBuilder.toString() => Text 54....
new StringBuilder.toString() => Text 55....
new StringBuilder.toString() => Text 56....
new StringBuilder.toString() => Text 57....
new StringBuilder.toString() => Ciphertext....
new StringBuilder.toString() => Plaintext:....
new StringBuilder(Calling ht...);
new StringBuilder.toString() => Calling ht....
new StringBuilder(Calling ht...);
new StringBuilder.toString() => Calling ht....
new StringBuilder(Calling ht...);
new StringBuilder.toString() => Calling ht....
new StringBuilder.toString() => Text 58....
```

- We have intercepted internal StringBuilder workings :)

### Replacing values

- We can intercept application communication, but we might want to change it
- Be cautious when changing items, you might change more than you would like to!
- Lets change the string output for the app's `IO` function

```javascript
mymatch = 'Hello Java World'
myreplace = 'Pwnd'

function myfunction() {
    // Check if frida has located the JNI
    if (Java.available) {

        // Switch to the Java context
        Java.perform(function() {
            const StringBuilder = Java.use('java.lang.StringBuilder');
            StringBuilder.toString.implementation = function () {   
                res = this.toString()
                // Check if the result is null, since we can't call methods on null!
                if (res !== null) {
                    // Does it match expectation?
                    if (res.match(mymatch)) {
                        // Replace the value
                        res = myreplace
                    }
                }
                return res
            }
        }
    )}
}
// Call the function
myfunction()
```

### HTTPS reading
-  We can read HTTPS traffic in several ways, depending on the implementation
-  If StringBuilder is used, you might use the previous example to read traffic
-  But we might want to now more, like the headers for instance

- Checkout the implementation in `jadx-gui` -> `startHttpsDemo`

```java
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, trustAllCerts, new SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
String urlString = "https://2017.hack.lu/?xyz=".concat(random(8));
MainActivity.processOutput("Calling ".concat(urlString));
HttpsURLConnection urlConnection = (HttpsURLConnection) new URL(urlString).openConnection();
urlConnection.setRequestMethod("GET");
int responseCode = urlConnection.getResponseCode();
MainActivity.processOutput(urlConnection.getResponseMessage());
if (responseCode < 400) {
    InputStream inputStream2 = new BufferedInputStream(urlConnection.getInputStream());
    try {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream2, "UTF-8"), 8);
        StringBuilder stringBuilder = new StringBuilder();
        while (true) {
            String line = reader.readLine();
            if (line == null) {
                break;
            }
            stringBuilder.append(line + "\n");
        }
        MainActivity.processOutput(stringBuilder.toString());

        ...
    }
}
```

-  Below the surface the class `com.android.okhttp.internal.huc.HttpURLConnectionImpl` is used to make HTTP(S) connections.

- Lets create a hook to inspect what is being returned by the server

```javascript
function myfunction() {
    if (Java.available) {
        Java.perform(function() {
            // Reference: https://developer.android.com/reference/java/net/HttpURLConnection.html
            clazz = 'com.android.okhttp.internal.huc.HttpURLConnectionImpl'
            const HttpURLConnection = Java.use(clazz)
            console.log('[+] Using class: ' + HttpURLConnection)
            console.log('[+] Handle "getInputStream": ' + HttpURLConnection.getInputStream.handle)


            // Here we will hook the implementation of the method getInputStream.
            // This method has NO overloads!
            HttpURLConnection.getInputStream.implementation = function() {
                console.log('[+] Inside "getInputStream" hook')

                // getHeaderFields returns a Map:
                // https://docs.oracle.com/javase/7/docs/api/java/util/Map.html#entrySet()
                // https://docs.oracle.com/javase/7/docs/api/java/util/Set.html
                console.log('[+] Headers: ' + this.getHeaderFields().entrySet().toArray())

                // We call the original getInputStream and store the result in stream.
                var stream = this.getInputStream();

                Java.perform(function() {
                    // The creation of new class instances (below) requires another Java.perfom inside this hook.

                    // Use the InputStream reader class
                    var InputStreamReader = Java.use('java.io.InputStreamReader');

                    // Create a new InputStreamReader object using $new.
                    // This constructor has NO overloads.
                    var isr = InputStreamReader.$new(stream, 'UTF-8');
                    console.log('[+] InputStreamReader instance: ' + isr)

                    // Use the BufferedReader reader class
                    var BufferedReader = Java.use('java.io.BufferedReader');

                    // Create a new InputStreamReader object using $new.
                    // This constructor does have overloads (2). Define the one we need using .overload and call it.
                    // Notice the difference in syntax.
                    console.log('[+] BufferedReader handle: ' + BufferedReader.$new.overload('java.io.Reader').handle)
                    var reader = BufferedReader.$new.overload('java.io.Reader').call(BufferedReader, isr);

                })
                // Pass the stream to the original caller.
                return stream
            }
        })
    }
}
// Call the function
myfunction()
```

__Output__

```
[+] Using class: <com.android.okhttp.internal.huc.HttpURLConnectionImpl>
[+] Handle "getInputStream": 0x6fcbbcf4
undefined
[Remote::gadget]-> [+] Inside "getInputStream" hook
[+] Headers: null=[HTTP/1.1 200 OK],Accept-Ranges=[bytes],Connection=[Keep-Alive],Content-Type=[text/html],Date=[Fri, 16 Feb 2018 10:04:20 GMT],ETag=["275c-55ba2ccb9996d-gzip"],Keep-Alive=[timeout=5, max=100],Last-Modified=[Mon, 16 Oct 2017 04:54:21 GMT],Server=[Apache],Vary=[Accept-Encoding],X-Android-Received-Millis=[1518776022135],X-Android-Response-Source=[NETWORK 200],X-Android-Selected-Protocol=[http/1.1],X-Android-Sent-Millis=[1518776022114]
[+] InputStreamReader instance: java.io.InputStreamReader@748c941
[+] BufferedReader handle: 0x6fa7abec
```

- Make the above function also display the lines of content in the page. The `BufferedReader` is already there ;)

### HTTPS Pinning bypass

- There are a multiple of ways to circumvent HTTPS pinning
- We could overwrite the stored certificate
    + Question: Where could that certificate be stored?
- We could try to return a `true` where the SSL implementation would otherwise return a `false`, when cecking the certificate 

- We also noticed the following trick: Overwrite the `TrustMananagerFactory` setting of the keystore to `null`, will allow all certificates :)
    + This trick requires that the TrustManager has not been previously initialized. Some caching by Android seems to occur!
    + Kill the application, start it and run the hook below.

```javascript
if (Java.available) {
    Java.perform(function () {
        TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
        TrustManagerFactory.init.overload('java.security.KeyStore').implementation = function(keystore) {
            console.log("Overwriting keystore to null")
            return this.init(null);
        }
    })
}
```

### Android Keystore

- The Android Keystore is used to save secrets
- We have saved a certificate but the keystore is protected with a password
- Can you grab the password using Frida?
- Look at the specification: https://docs.oracle.com/javase/7/docs/api/java/security/KeyStore.html
    + `load(InputStream stream, char[] password)`

```javascript
if (Java.available) {
    Java.perform(function () {
        KeyStore = Java.use('java.security.KeyStore');
    })
}
```

### Crypto

- A common library to use for Crypto in Android is `javax.crypto.Cipher`
- It will use `javax.crypto.spec.SecretKeySpec` to define what sort of cryptography is being used: https://docs.oracle.com/javase/7/docs/api/javax/crypto/spec/SecretKeySpec.html

```
SecretKeySpec(byte[] key, String algorithm)
Constructs a secret key from the given byte array.
```

- Can you show the AES key being used?

```javascript
if (Java.available) {
    Java.perform(function () {
        String = Java.use("java.lang.String")

        SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload(...)
        }
    });
}
```

- Can you show the data being encrypted/decrypted in Frida?

```javascript
if (Java.available) {
    Java.perform(function () {
        String = Java.use("java.lang.String")

        Cipher = Java.use('javax.crypto.Cipher')
        Cipher.doFinal.overload(...)
        }
    });
}
```

- Okay thats it for the introduction!
