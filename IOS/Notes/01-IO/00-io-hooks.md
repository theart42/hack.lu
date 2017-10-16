## Sample application: Omed

### I/O

- Reads a txt file from disk.

__Swift__
```swift
let path = Bundle.main.path(forResource: "file", ofType: "txt")
if (path != nil) {
    let fileContents = try String(contentsOfFile: path! ,encoding: String.Encoding.utf8)
    return fileContents
```

__Dissasembled__
```c
 if ((Swift.!= infix<A where A: Swift.Equatable>() & 0x1) != 0x0) {
            __T0SqWy_17fec();
            if ((stack[1989] & 0x1) != 0x0) {
                    function signature specialization <preserving fragile attribute, Arg[2] = Dead, Arg[3] = Dead> of Swift._fatalErrorMessage();
            }
            *(extension in Foundation):Swift.String.Encoding.utf8.unsafeMutableAddressor : (extension in Foundation):Swift.String.Encoding();
            *(sp + 0x4) = r7 - 0x6c;
            stack[1982] = (extension in Foundation):Swift.String.init(contentsOfFile: Swift.String, encoding: (extension in Foundation):Swift.String.Encoding) throws -> Swift.String();
            stack[1981] = stack[1987];
            stack[1980] = stack[1988];
            stack[1979] = 0x0;
            if (0x0 == 0x0) {
                    __T0SqWe_18018();
                    stack[1975] = stack[1982];
                    stack[1974] = stack[1981];
                    stack[1973] = stack[1980];
            }
        }
```

- Note: Although we see the 'high level' code, all file manipulation will result in actions in `libc`, to pass calls to the kernel through 'syscalls'. Eg: `open`, `read`, `write` etc.
- Tracing with `frida-trace`. Note: execute from a temporary directory, it will create a directory `__handlers__`.
```shell
# Simulator
frida-trace -R Gadget -i 'open' -i 'read' -i 'write'

# Device
frida-trace -U Gadget -i 'open' -i 'read' -i 'write'
```

- Output `frida-trace`
```shell
Instrumenting functions...
open: Auto-generated handler at "/private/tmp/__handlers__/libsystem_sim_kernel_host.dylib/open.js"
read: Auto-generated handler at "/private/tmp/__handlers__/libsystem_sim_kernel_host.dylib/read.js"
write: Auto-generated handler at "/private/tmp/__handlers__/libsystem_sim_kernel_host.dylib/write.js"
Started tracing 3 functions. Press Ctrl+C to stop.
           /* TID 0x403 */
 10108 ms  open()
 10109 ms  read()
```

- Hooking the functions in `frida` REPL

```javascript
//How many charactes should be printed in hexview max.
MAXHEXDISPLAY = 1000;

//Store open file handles
known_file_handles = {};

// Intercept the open call.
Interceptor.attach(Module.findExportByName(null,'open'), {
    onEnter: function (args) {
        //On entering the function log the call.
        //args[0] = char *pathname
        //args[1] = int flags
        
        //save argument(s) for result
        this.filename = Memory.readUtf8String(args[0]);
        this.msg = 'open("' + this.filename +'"' +', ' +args[1] + ')';
        console.log(this.msg);
    },
    onLeave: function (retval) {
        //On leaving the function log the call and its return value
        console.log(this.msg +' => ' + retval);
        this.filehandle = retval.toInt32();

        //Globally remember the filehandle / filename mapping.
        if (this.filehandle != -1) {
            known_file_handles[this.filehandle] = this.filename;
        } 
    }
})

// Intercept the write call.
Interceptor.attach(Module.findExportByName(null, 'write'), {
    onEnter: function (args) {
        //On entering the function log the call.
        //args[0] = filedescriptor
        //args[1] = buffer to be written
        //args[2] = nr of bytes to write
        
        //Check if we know the filename for the handle, otherwise use the number.
        fd = args[0].toInt32();
        if (known_file_handles[fd]) {
            this.msg = 'write("' + known_file_handles[fd] + '", ' + args[1] + ', ' + args[2] + ")";
        }
        else {
            this.msg = 'write(' + args[0] + ', ' + args[1] + ', ' + args[2] + ")";
        }
        console.log(this.msg);

        //Print the bytes to be written
        size = args[2].toInt32()
        if (size > MAXHEXDISPLAY) {
                size = MAXHEXDISPLAY
        }   
        if (size > 0) {
            console.log(hexdump(ptr(args[1]), {
                length: size,
                header: true,
                ansi: true
            }));
        }
    },
    onLeave: function (retval) {
        //On leaving the function log the call and its return value
        console.log(this.msg +' => ' + retval);
    }

})

// Intercept the read call.
Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function (args) {
        //On entering the function log the call.
        //args[0] = filedescriptor
        //args[1] = buffer to be read to
        //args[2] = nr of bytes to read

        //Remember the buffer location for onLeave
        this.buffer = args[1];
        
        //Check if we know the filename for the handle, otherwise use the number.
        fd = args[0].toInt32();
        if (known_file_handles[fd]) {
            this.msg = 'read("' + known_file_handles[fd] + '", ' + args[1] + ', ' + args[2] + ")";
        }
        else {
            this.msg = 'read(' + args[0] + ', ' + args[1] + ', ' + args[2] + ")";
        }
        console.log(this.msg)
    },
    onLeave: function(result) {
        //On leaving the function show the data read.
        size = result.toInt32();
        
        if (size > MAXHEXDISPLAY) {
            size = MAXHEXDISPLAY;
        }
        //Use the buffer stored in onEnter to display data read
        if (size > 0) {
            if (this.buffer != null) {
                console.log(hexdump(ptr(this.buffer), {
                        length: size,
                        header: true,
                        ansi: true
                }));
            }
        }
    }
})
```
