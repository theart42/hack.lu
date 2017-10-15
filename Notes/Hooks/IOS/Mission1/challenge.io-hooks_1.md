### Challenge 1

- References: https://www.frida.re/docs/javascript-api/#memory
- Replace the current text displayed, with one of your own.
    + You can use `Memory.writeByteArray(ptr, new ArrayBuffer(size))` to set the current buffer to 0's. 
    + You can use `Memory.writeUtf8String(ptr, string)` to write the string.
- Make sure it fits in the buffer provided to the `read` call
    + You could use the size returned by the actual `read` call
    + You could use the size given to `read` function by the caller
- When should the buffer be overwritten? `onEnter`, or `onLeave`?