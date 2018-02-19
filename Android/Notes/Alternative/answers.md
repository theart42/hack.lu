### Answers

- Show the lines in HTTPS:

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
                     // Loop through all the lines
                    while ((line = reader.readLine()) != null) {
                        console.log(line);
                    }

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

### Keystore

```javascript
if (Java.available) {
    Java.perform(function () {
        KeyStore = Java.use('java.security.KeyStore');
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(stream, password) {
            if (password != null) {
                console.log("KeyStore loaded with password: " + password)
            }
            else {
                console.log("KeyStore loaded without password")
            }
            console.log("Stream: " + stream)
            return this.load(stream, password)
        }
    })
}
```

### Crypto

- AES Key:

```javascript
if (Java.available) {
    Java.perform(function () {
        String = Java.use("java.lang.String")

        SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, type) {
            console.log("[+] Key: " + key)
            console.log("[+] Type: " + type)
            return this.$init(key,type)
        }

    });
}
```

- Data:

```javascript
if (Java.available) {
    Java.perform(function () {
        String = Java.use("java.lang.String")

        Cipher = Java.use('javax.crypto.Cipher')
        Cipher.doFinal.overload('[B').implementation = function(bytes) {
            s = String.$new(bytes, "UTF-8")
            console.log("[+] Data: " + s)
            return this.doFinal(bytes)  
        }
    });
}
```

String str = new String('hello');
[               ]
String.$new('My new string')

$new
    $alloc
$init