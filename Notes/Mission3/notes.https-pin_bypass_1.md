## Sample application: Omed

### HTTPS-Pin

- Uses a pinned certificate to access a HTTPS website. The pinned certificate is incorrect on purpose. We will need to bypass this pinning.

- The following code works against IOS (iPhone 4 checked!) devices. The IOS simulator won't be bypassed this way!
https://raw.githubusercontent.com/vtky/Swizzler2/master/SSLKillSwitch.js

```javascript
/*
    Thanks to Alban Diquet for his SSL Kill Switch 2 project - https://github.com/nabla-c0d3/ssl-kill-switch2
*/

'use strict';


/*
    Stuff from nabla-c0d3's SSL Kill Switch 2 (https://github.com/nabla-c0d3/ssl-kill-switch2) converted to run with Frida.

    No idea currently why all of this does not work with iOS 10.
*/
var errSSLServerAuthCompleted = -9481; /* <Security/SecureTransport.h> peer cert is valid, or was ignored if verification disabled */
var kSSLSessionOptionBreakOnServerAuth = 0;
var noErr = 0;

/* OSStatus SSLHandshake ( SSLContextRef context ); */
var SSLHandshake = new NativeFunction(
    Module.findExportByName("Security", "SSLHandshake"),
    'int',
    ['pointer']
);

Interceptor.replace(SSLHandshake, new NativeCallback(function (context) {
    var result = SSLHandshake(context);

    // Hijack the flow when breaking on server authentication
    if (result == errSSLServerAuthCompleted) {
        console.log("Relacing SSLHandshake");
        // Do not check the cert and call SSLHandshake() again
        return SSLHandshake(context);
    }

    return result;
}, 'int', ['pointer']));


/* SSLContextRef SSLCreateContext ( CFAllocatorRef alloc, SSLProtocolSide protocolSide, SSLConnectionType connectionType ); */
var SSLCreateContext = new NativeFunction(
    Module.findExportByName("Security", "SSLCreateContext"),
    'pointer',
    ['pointer', 'int', 'int']
);

Interceptor.replace(SSLCreateContext, new NativeCallback(function (alloc, protocolSide, connectionType) {
    console.log("Relacing SSLCreateContext");
    var sslContext = SSLCreateContext(alloc, protocolSide, connectionType);

    // Immediately set the kSSLSessionOptionBreakOnServerAuth option in order to disable cert validation
    SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, 1);
    return sslContext;
}, 'pointer', ['pointer', 'int', 'int']));


/* OSStatus SSLSetSessionOption ( SSLContextRef context, SSLSessionOption option, Boolean value );*/
var SSLSetSessionOption = new NativeFunction(
    Module.findExportByName("Security", "SSLSetSessionOption"),
    'int',
    ['pointer', 'int', 'bool']
);

Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (context, option, value) {
    // Remove the ability to modify the value of the kSSLSessionOptionBreakOnServerAuth option
    if (option == kSSLSessionOptionBreakOnServerAuth) {
        console.log("Relacing SSLSetSessionOption");
        return noErr;
    }
    return SSLSetSessionOption(context, option, value);
}, 'int', ['pointer', 'int', 'bool']));

/*
    The old way of killing SSL Pinning
*/

// SecTrustResultType
var kSecTrustResultInvalid = 0;
var kSecTrustResultProceed = 1;
// var kSecTrustResultConfirm = 2 // Deprecated
var kSecTrustResultDeny = 3;
var kSecTrustResultUnspecified = 4;
var kSecTrustResultRecoverableTrustFailure = 6;
var kSecTrustResultFatalTrustFailure = 6;
var kSecTrustResultOtherError = 7;


/*
    OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
*/
var SecTrustEvaluate = new NativeFunction(
    Module.findExportByName("Security", "SecTrustEvaluate"),
    'int',
    ['pointer', 'pointer']
);

Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
    console.log("Relacing SecTrustEvaluate");
    var ret = SecTrustEvaluate(trust, result);
    result = kSecTrustResultProceed;
    return ret;
}, 'int', ['pointer', 'pointer']));


/*
    Killing SSL Pinning of some of the commonly encountered frameworks
*/

if (ObjC.classes.AFSecurityPolicy) {
    /* AFNetworking */
    Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
        onEnter: function (args) {
            console.log("Relacing AFSecurityPolicy setSSLPinningMode = 0 was " + args[2]);
            args[2] = ptr('0x0');
        }
    });

    Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
        onEnter: function (args) {
            console.log("Relacing AFSecurityPolicy setAllowInvalidCertificates = 1 was " + args[2]);
            args[2] = ptr('0x1');
        }
    });
}


if (ObjC.classes.KonyUtil) {
    /* Kony */
    Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowSelfSignedCertificate'].implementation, {
        onLeave: function (retval) {
            console.log("Relacing KonyUtil shouldAllowSelfSignedCertificate = 1 was " + retval);
            retval.replace(0x1);
        }
    });

    Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledWithSystemDefault'].implementation, {
        onLeave: function (retval) {
            console.log("Relacing KonyUtil shouldAllowBundledWithSystemDefault = 1 was " + retval);
            retval.replace(0x1);
        }
    });


    Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledOnly'].implementation, {
        onLeave: function (retval) {
            console.log("Relacing KonyUtil shouldAllowBundledOnly = 0 was " + retval);
            retval.replace(0x0);
        }
    });
}




/*
    Other uncommon crap that I come across
*/

if (ObjC.classes.VGuardManager) {
    /* vkey */
    Interceptor.attach(ObjC.classes.VGuardManager['- setEnableSSLPinning:'].implementation, {
        onEnter: function (args) {
            console.log("Relacing VGuardManager setEnableSSLPinning = 0 was " + args[2]);
            args[2] = ptr('0x0');
        }
    });
}


if (ObjC.classes.eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI) {
    Interceptor.attach(ObjC.classes.eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI['- setIsSSLHookDetected:'].implementation, {
        onEnter: function (args) {
            console.log("Relacing eAhJgIkSdNCToZQwjpbnNbjfvZlYUSbyIFtfxkXSgI setIsSSLHookDetected = 0 was " + args[2]);
            args[2] = ptr('0x0');
        }
    });
}
```

- Look at the implementation

__Swift__
```swift
let url = URL(string: "https://2017.hack.lu/?xyz=" +
            Utils.randomAlphaNumericString(length: 16)
        )
        let session = URLSession(configuration: URLSessionConfiguration.default, delegate: URLSessionPinningDelegate(), delegateQueue: nil)
```

```swift
//
// https://stackoverflow.com/questions/34223291/ios-certificate-pinning-with-swift-and-nsurlsession
//
class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Swift.Void) {
        
        // Adapted from OWASP https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#iOS
        
        if (challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust) {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)
                
                if(errSecSuccess == status) {
                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
                        let serverCertificateData = SecCertificateCopyData(serverCertificate)
                        let data = CFDataGetBytePtr(serverCertificateData);
                        let size = CFDataGetLength(serverCertificateData);
                        let cert1 = NSData(bytes: data, length: size)
                        let file_der = Bundle.main.path(forResource: "pinned", ofType: "cer")
                        
                        if let file = file_der {
                            if let cert2 = NSData(contentsOfFile: file) {
                                if cert1.isEqual(to: cert2 as Data) {
                                    completionHandler(URLSession.AuthChallengeDisposition.useCredential, URLCredential(trust:serverTrust))
                                    return
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Pinning failed
        completionHandler(URLSession.AuthChallengeDisposition.cancelAuthenticationChallenge, nil)
```

__Decompiled__
```c
int __TZFC4Omed15OmedSimpleHTTPS13requestPinnedfT15completionBlockFSST__T_(int arg0, int arg1, int arg2) {
    r7 = sp - 0x8;
    var_30 = arg0;
    var_34 = arg1;
    Swift.String.init();
    var_38 = Foundation.URL.init();
    var_3C = type metadata accessor for __ObjC.URLSession();
    r0 = type metadata accessor for __ObjC.URLSessionConfiguration();
    var_40 = r0;
    var_44 = r0;
    if (*r0 == 0xe) {
            var_44 = *(var_40 + 0x4);
    }
    r7 = r7;
    stack[2025] = @nonobjc __ObjC.URLSession.__allocating_init([[var_44 defaultSessionConfiguration] retain], Omed.URLSessionPinningDelegate.__allocating_init(type metadata accessor for Omed.URLSessionPinningDelegate()), 0x0, var_3C);
    __T0SqWy_15a34(var_38);
    if (var_38 == 0x0) {
            stack[2007] = 0x2 & 0xff;
            function signature specialization <preserving fragile attribute, Arg[2] = Dead, Arg[3] = Dead> of Swift._fatalErrorMessage();
    }
```

- An alternative way I found is overwriting the URLSessionConfiguration delegate to NULL.
- Tracing with `frida-trace`
```shell
# Simulator
frida-trace -R Gadget -m '-[*NSURLSession* *Configuration*delegate*]'

# Device
frida-trace -U Gadget -m '-[*NSURLSession* *Configuration*delegate*]'
```

```shell
Instrumenting functions...
-[__NSURLSessionLocal initWithConfiguration:delegate:delegateQueue:]: Loaded handler at "/private/tmp/__handlers__/____NSURLSessionLocal_initWithCo_7c762fb4.js"
-[NSURLSession initWithConfiguration:delegate:delegateQueue:]: Loaded handler at "/private/tmp/__handlers__/__NSURLSession_initWithConfigura_-2e32aa6b.js"
-[__NSCFURLSession initWithConfiguration:delegate:delegateQueue:]: Loaded handler at "/private/tmp/__handlers__/____NSCFURLSession_initWithConfi_-9fdbc4f.js"
-[__NSURLBackgroundSession initWithConfiguration:delegate:delegateQueue:]: Loaded handler at "/private/tmp/__handlers__/____NSURLBackgroundSession_initW_-67f5ee66.js"
Started tracing 4 functions. Press Ctrl+C to stop.
           /* TID 0xa0b */
  3403 ms  -[__NSURLSessionLocal initWithConfiguration:0x1576b780 delegate:0x1576b6c0 delegateQueue:0x0 ]
  3404 ms     | -[__NSCFURLSession initWithConfiguration:0x1576b780 delegate:0x1576b6c0 delegateQueue:0x0 ]
  3404 ms     |    | -[NSURLSession initWithConfiguration:0x1576b780 delegate:0x1576b6c0 delegateQueue:0x0 ]
```

- Hooking the functions in `frida` REPL

```javascript
// Intercept the -[__NSURLSessionLocal initWithConfiguration:delegate:delegateQueue:] call.
Interceptor.attach(ObjC.classes.__NSURLSessionLocal['- initWithConfiguration:delegate:delegateQueue:'].implementation, {
    onEnter: function (args) {
      this.msg = '-[__NSURLSessionLocal initWithConfiguration:' +args[2] +' delegate:' +args[3] +' delegateQueue:' +args[4] +']'
      console.log(this.msg)      
     
      //Replace the argument with a pointer to 0x0, to remove the delegate from the execution path.
      args[3] = NULL
      this.msg = '-[__NSURLSessionLocal initWithConfiguration:' +args[2] +' delegate:' +args[3] +' delegateQueue:' +args[4] +']'
      console.log('Replaced argument: ' + this.msg)
    },
    onLeave: function (retval) {
       console.log(this.msg +' => ' + retval);
    } 
});

```

- Example output:

```
-[__NSURLSessionLocal initWithConfiguration:0x157753b0 delegate:0x157754e0 delegateQueue:0x0]
Replaced argument: -[__NSURLSessionLocal initWithConfiguration:0x157753b0 delegate:0x0 delegateQueue:0x0]
-[__NSURLSessionLocal initWithConfiguration:0x157753b0 delegate:0x0 delegateQueue:0x0] => 0x157768d0
```