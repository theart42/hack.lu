## Sample application: Omed

### HTTPS

- Reads a HTTPS website. Lets try to peek into the communication.

__Swift__
```swift
    static func request(completionBlock: @escaping (String) -> Void) -> Void {
        let url = URL(string: "https://2017.hack.lu/?xyz=" +
            Utils.randomAlphaNumericString(length: 16)
        )
        let session = URLSession(configuration: URLSessionConfiguration.default)
        let task = session.dataTask(with: url!, completionHandler: { data, response, error in
            if(error != nil) {
                print("Error: \(String(describing: error))")
            }
            else {
                completionBlock(String(data: data!, encoding: .utf8)!)
            }
        })
        task.resume()
    }
```

```swift
    @IBAction func readHTTPS()  
    {
        OmedSimpleHTTPS.request() { (output) in
            DispatchQueue.main.async {
                self.TextViewOutput.text = output
            }
        }
    }
```

__Dissasembled__
```
 r7 = r7;
    stack[2023] = @nonobjc __ObjC.URLSession.__allocating_init([[stack[2025] defaultSessionConfiguration] retain]);
    __T0SqWy_15964(var_4C);
    if (var_4C != 0x0) {
            stack[2022] = var_4C;
    }
    else {
            stack[2004] = 0x2 & 0xff;
            function signature specialization <preserving fragile attribute, Arg[2] = Dead, Arg[3] = Dead> of Swift._fatalErrorMessage();
    }
    Foundation.URL._bridgeToObjectiveC();
    [stack[2022] release];
    _swift_rt_swift_retain();
    r0 = _swift_rt_swift_allocObject();
    *(r0 + 0xc) = var_30;
    *(r0 + 0x10) = var_34;
    _Block_copy(r7 - 0x2c);
    _swift_rt_swift_release();
    [[stack[2023] dataTaskWithURL:stack[2018] completionHandler:stack[2016], 0x39] retain];
    _Block_release(stack[2016]);
    [stack[2018] release];
    [stack[2014] retain];
    [stack[2014] resume];
    [stack[2014] release];
    [stack[2014] release];
    [stack[2023] release];
    __T0SqWe_159ac(var_4C);
    _swift_rt_swift_release();
    r0 = stack[2014];
    return r0;
```

- Tracing with `frida-trace`. Note: execute from a temporary directory, it will create a directory `__handlers__`.
```shell
# Simulator
frida-trace -R gadget -m '-[NSURLSession dataTaskWithURL:*]'

# Device
frida-trace -U gadget -m '-[NSURLSession dataTaskWithURL:*]'
```

- Output `frida-trace`

```shell
Instrumenting functions...
-[NSURLSession dataTaskWithURL:completionHandler:]: Auto-generated handler at "/private/tmp/__handlers__/__NSURLSession_dataTaskWithURL_c_01cef27d.js"
-[NSURLSession dataTaskWithURL:]: Auto-generated handler at "/private/tmp/__handlers__/__NSURLSession_dataTaskWithURL__.js"
Started tracing 2 functions. Press Ctrl+C to stop.
           /* TID 0x303 */
  4206 ms  -[NSURLSession dataTaskWithURL:0x6040002e3b80 completionHandler:0x604000447f80 ]
```

- Hooking the function in Frida. It overrides the completion handler and displays its parameters, after that it will call the original completion handler.

```javascript
stored = null

Interceptor.attach(ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
    onEnter: function (args) {
        this.title = "-[NSURLSession dataTaskWithRequest:completionHandler:]"
        console.log("Enter " + this.title)
        // ObjC parameters start at args[2]. 
        // args[0] = self
        console.log("Self: " + args[0])
        // args[1] = selector (method identifier)
        console.log("Selector: " + args[1])
        requestObj = ObjC.Object(args[2])
        console.log("Request " + requestObj)
        // Store the original completion block (outside this scope).
        completionHandler = new ObjC.Block(args[3])
        stored = completionHandler.implementation
        completionHandler.implementation = function (data, response, error) {
            console.log("Response: " + requestObj)
            console.log(ObjC.Object(response))
            // 'data' is a NSData object.
            // 1. convert the pointer to an object
            d = ObjC.Object(data)
            len = d.length()
            // 2. get its bytes
            d = d.bytes()
            // 3. dump the data
            // This sometimes fails: console.log(Memory.readUtf8String(d))
            console.log(hexdump(d, {ansi:true, length:len}))
            // Call the original completion block
            return stored(data, response, error)
        }
    },
    onLeave: function (retval) {
        console.log("Leave " + this.title)
    }
})
```

- An alternative could be hooking the TLS functions. This does not work in the simulator, but does work on a iPhone 4s.

```javascript
//How many charactes should be printed in hexview max.
MAXHEXDISPLAY = 1000;

Interceptor.attach(Module.findExportByName(null,'tls_record_encrypt'), {
    onEnter: function (args) {
        this.count = args[1].toInt32()
        this.data  = args[2]

        this.msg = "tls_record_encrypt(" +args[0] +", " +this.count +", " +this.data +", " +args[3] + ")"
        console.log(this.msg)

        size = this.count
        if (size > MAXHEXDISPLAY) {
            size = MAXHEXDISPLAY;
        }
        if (size > 0) {
            console.log(hexdump(ptr(this.data), {
                length: size,
                header: true,
                ansi: true
            }))
        }
    }
})

Interceptor.attach(Module.findExportByName(null,'tls_record_decrypt'), {
    onEnter: function (args) {
        this.count = args[1].toInt32()
        this.data  = args[2]

        this.msg = "tls_record_decrypt(" +args[0] +", " +this.count +", " +this.data +", " +args[3] + ")"
        console.log(this.msg)
    },
    onLeave: function (retval) {
        size = this.count
        if (size > MAXHEXDISPLAY) {
            size = MAXHEXDISPLAY;
        }
        if (size > 0) {
            console.log(hexdump(ptr(this.data), {
                length: size,
                header: true,
                ansi: true
            }))
        }
    }
})
```


