### Solution 1

```javascript

REPLACE_TEXT = "Hahahaha I just changed you!"

Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function (args) {
        //On entering the function log the call.
        //args[0] = filedescriptor
        //args[1] = buffer to be read to
        //args[2] = nr of bytes to read

        //Remember the buffer location for onLeave
        this.buffer = args[1];
    },
    onLeave: function(result) {
        //Returned size of the original
        size = result.toInt32();
        //Slice the text to fit into the buffer
        msg = REPLACE_TEXT.slice(0, size - 1)
        //Empty the current buffer (set all positions to 0)
        Memory.writeByteArray(this.buffer, new ArrayBuffer(size))
        //Write the new message
        Memory.writeUtf8String(this.buffer, msg)
    }
})
```
