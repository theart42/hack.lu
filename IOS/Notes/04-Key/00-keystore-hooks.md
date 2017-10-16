## Sample application: Omed

### Key

- Loads an application password from the keystore 

__Swift__

```swift
 public static func read() -> String{
        let accountName = "Omed"
        let passwordItem = KeychainPasswordItem(service: KeychainConfiguration.serviceName, account: accountName, accessGroup: KeychainConfiguration.accessGroup)

        do {
            let password = try passwordItem.readPassword()
            return password
        }
        catch {
            let msg = "Error loading password"
            print(msg)
            return msg
        }
```

```swift
// Try to fetch the existing keychain item that matches the query.
var queryResult: AnyObject?
let status = withUnsafeMutablePointer(to: &queryResult) {
    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
}
```


__Dissasembled__
```
int __TFFV4Omed20KeychainPasswordItem12readPasswordFzT_SSU_FGSpGSqPs9AnyObject___Vs5Int32(int arg0, int arg1) {
    outlined copy of Swift._VariantDictionaryBuffer(*arg1);
    type metadata accessor for Swift.AnyObject();
    (extension in Foundation):Swift.Dictionary._bridgeToObjectiveC() -> __ObjC.NSDictionary();
    outlined copy of Swift._VariantDictionaryBuffer with unmangled suffix ".1"(*arg1);
    stack[2039] = SecItemCopyMatching(stack[2040], arg0);
    [stack[2040] release];
    r0 = stack[2039];
    return r0;
}
```

- Tracing with `frida-trace`
```shell
# Simulator
frida-trace -R Gadget -i 'SecItemCopyMatching'

# Device
frida-trace -U Gadget -i 'SecItemCopyMatching'
```

```
Instrumenting functions...
SecItemCopyMatching: Auto-generated handler at "/private/tmp/__handlers__/Security/SecItemCopyMatching.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0xa0b */
  2297 ms  SecItemCopyMatching()
```

- Hooking the functions in `frida` REPL

```javascript
// Intercept the SecItemCopyMatching call.
Interceptor.attach(Module.findExportByName(null,'SecItemCopyMatching'), {
    onEnter: function (args) {
        this.query = ObjC.Object(args[0])
        this.result = args[1]
        this.msg = 'SecItemCopyMatching(' + args[0] +', ' +args[1], ')'

        this.msg = 'SecItemCopyMatching(' + 
            'query: '  + this.query  +', ' +
            'result: ' + this.result +')'

        console.log(this.msg)
    },
    onLeave: function(retval) {
        //The result is a pointer. Grab that
        p_result = Memory.readPointer(this.result)
        //Get the result object
        result = ObjC.Object(p_result)
        //Log the contents of the result
        console.log(result.toString())
        //Expand the byte array vData to a string
        v_Data = Memory.readUtf8String(result['+ valueForKey:']("v_Data").bytes())
        //Log the vData
        console.log('v_Data = ' + v_Data)
    }
})
```

- Example output:

```
SecItemCopyMatching(query: {
    acct = Omed;
    class = genp;
    "m_Limit" = "m_LimitOne";
    "r_Attributes" = 1;
    "r_Data" = 1;
    svce = OmedKeychainService;
}, result: 0x154310)
{
    acct = Omed;
    agrp = "R9P47YM6BH.Warpnet.Omed";
    cdat = "2017-09-09 15:02:52 +0000";
    mdat = "2017-09-09 15:02:52 +0000";
    musr = <>;
    pdmn = ak;
    svce = OmedKeychainService;
    sync = 0;
    tomb = 0;
    "v_Data" = <4f6d6564 2e736563 726574>;
}
v_Data = Omed.secret
```

