## Sample application: Omed

### HTTPS

- Reads a HTTPS website. Lets try to peek into the communication.

TODO
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
