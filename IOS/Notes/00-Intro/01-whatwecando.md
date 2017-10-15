### What can we do in Frida

- Replace:
    + Functions / Completion handlers / Delegates
        * Arguments
        * Return values

- Trace the call stack

### Basic example:

- Find a c or c++ function using: `Module.findExportByName`.
- Attach an interceptor on entering and on leaving that function (or method) using: `Interceptor.attach`.
- Save values during the function entering, to be used when leaving/
- Show the current threadId, registers, return address etc.
- Show the calling stack up to our function call.
- Hexdump a buffer.
- Reference: https://www.frida.re/docs/javascript-api/

```javascript
Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function (args) {
        // Display the context
        console.log('Context information:');
        console.log('Context  : ' + JSON.stringify(this.context));
        console.log('Return   : ' + this.returnAddress);
        console.log('ThreadId : ' + this.threadId);
        console.log('Depth    : ' + this.depth);
        console.log('Errornr  : ' + this.err);

        // Backtrace
        console.log("Called from: \n" +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n") + "\n");

        // Save arguments for processing in onLeave.
        this.fd    = args[0].toInt32();
        this.buf   = args[1];
        this.count = args[2].toInt32();
    },
    onLeave: function (result) {
        console.log('----------')
        // Show argument 1 (buf), saved during onEnter.
        numBytes = result.toInt32();
        if (numBytes > 0) {
            console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
        }
        console.log('Result   : ' + numBytes);
    }
})
```

- To clear all current interceptions: `Interceptor.detachAll()`