## Sample application: Omed

### Crypt

- Encrypt / Decrypt a message with a random key

__Swift__
```swift
let key = randomAlphaNumericString(length: 16)

let enc = c.cryptography(msg.data(using: .utf8)!, key: key, operation: Cryptor.encrypt)
let dec = c.cryptography(enc!, key: key, operation: Cryptor.decrypt)
return String(data: dec!, encoding: .utf8)!
```

```swift
class Cryptor {
    public static let encrypt = CCOperation(kCCEncrypt)
    public static let decrypt = CCOperation(kCCDecrypt)
    
    func cryptography(_ inputData: Data, key: String, operation: CCOperation) -> Data? {
        
        //prepare the Key
        let keyData = key.data(using: .utf8, allowLossyConversion: false)!
        let keyLength = kCCKeySizeAES128
        
        //Prepare the input data
        
        //Check whether this is encryption , if so generate a random  IV and append this to the encrypted data
        let ivData :Data
        let data: Data
        if operation == CCOperation(kCCEncrypt) {
            // ivData = self.generateIV()
            ivData = Data(repeating: 0, count: 16)
            data = inputData
        } else {
            //for decryption the last 16 bytes will be the IV so extract it
            let rangStart = inputData.count - kCCBlockSizeAES128
            let rangeEnd = inputData.count
            ivData = inputData.subdata(in: rangStart..<rangeEnd)
            data = inputData.subdata(in: 0..<rangStart)
        }
        let dataLength = data.count
        
        //Calculate buffer details
        var bufferData       = Data(count: dataLength + kCCBlockSizeAES128)
        let bufferLength     = bufferData.count
        
        var bytesDecrypted   = 0
        let cryptStatus = keyData.withUnsafeBytes {keyBytes in
            ivData.withUnsafeBytes {ivBuffer in
                data.withUnsafeBytes {dataBytes in
                    bufferData.withUnsafeMutableBytes {bufferPointer in
                        CCCrypt(
                            operation,                      // Operation
                            CCAlgorithm(kCCAlgorithmAES128),   // Algorithm is AES
                            CCOptions(kCCOptionPKCS7Padding), //options
                            keyBytes,                       // key data
                            keyLength,                      // key length
                            ivBuffer,                            // IV buffer
                            dataBytes,                      // input data
                            dataLength,                     // input length
                            bufferPointer,                  // output buffer
                            bufferLength,                   // output buffer length
                            &bytesDecrypted)                // output bytes decrypted real length
                    }
                }
            }
        }
```

- Find references to CCCrypt

__Dissasembled__
```c
    else {
            *((sp - 0x14) + 0xfffffffffffffffc) = r8;
            r0 = CCCrypt(r1, 0x0, 0x1, r2, type metadata for Swift.Int32, arg4, arg5, arg6, 0x0, arg7, arg8);
    }
```

- Tracing with `frida-trace`
```shell
# Simulator
frida-trace -R Gadget -i 'CCCrypt'

# Device
frida-trace -U Gadget -i 'CCCrypt'
```

```
Instrumenting functions...
CCCrypt: Loaded handler at "/private/tmp/__handlers__/libcommonCrypto.dylib/CCCrypt.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0xa0b */
  3227 ms  CCCrypt()
  3228 ms  CCCrypt()
```

- Hooking the functions in `frida` REPL

```javascript
// Intercept the CCCrypt call.
Interceptor.attach(Module.findExportByName(null, 'CCCrypt'), {
    onEnter: function (args) {
        // Save the arguments
        this.operation   = args[0]
        this.CCAlgorithm = args[1]
        this.CCOptions   = args[2]
        this.keyBytes    = args[3]
        this.keyLength   = args[4]
        this.ivBuffer    = args[5]
        this.inBuffer    = args[6]
        this.inLength    = args[7]
        this.outBuffer   = args[8]
        this.outLength   = args[9]
        this.outCountPtr = args[10]

        console.log('CCCrypt(' + 
            'operation: '   + this.operation    +', ' +
            'CCAlgorithm: ' + this.CCAlgorithm  +', ' +
            'CCOptions: '   + this.CCOptions    +', ' +
            'keyBytes: '    + this.keyBytes     +', ' +
            'keyLength: '   + this.keyLength    +', ' +
            'ivBuffer: '    + this.ivBuffer     +', ' +
            'inBuffer: '    + this.inBuffer     +', ' +
            'inLength: '    + this.inLength     +', ' +
            'outBuffer: '   + this.outBuffer    +', ' +
            'outLength: '   + this.outLength    +', ' +
            'outCountPtr: ' + this.outCountPtr  +')')

        if (this.operation == 0) {
            // Show the buffers here if this an encryption operation
            console.log("In buffer:")
            console.log(hexdump(ptr(this.inBuffer), {
                length: this.inLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("Key: ")
            console.log(hexdump(ptr(this.keyBytes), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("IV: ")
            console.log(hexdump(ptr(this.ivBuffer), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
        }
    },
    onLeave: function (retVal) {
        if (this.operation == 1) {
            // Show the buffers here if this a decryption operation
            console.log("Out buffer:")
            console.log(hexdump(ptr(this.outBuffer), {
                length: Memory.readUInt(this.outCountPtr),
                header: true,
                ansi: true
            }))
            console.log("Key: ")
            console.log(hexdump(ptr(this.keyBytes), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
            console.log("IV: ")
            console.log(hexdump(ptr(this.ivBuffer), {
                length: this.keyLength.toInt32(),
                header: true,
                ansi: true
            }))
        }
    }
})
```

- Example output:

```s
CCCrypt(operation: 0x0, CCAlgorithm: 0x0, CCOptions: 0x1, keyBytes: 0x16692078, keyLength: 0x10, ivBuffer: 0x166919d0, inBuffer: 0x16687138, inLength: 0x14, outBuffer: 0x16691eb0, outLength: 0x24, outCountPtr: 0x154470)
In buffer:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  4f 6d 65 64 20 63 72 79 70 74 20 64 65 63 72 79  Omed crypt decry
00000010  70 74 65 64                                      pted
Key:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  47 73 62 74 56 36 74 6f 50 55 66 56 50 47 55 6a  GsbtV6toPUfVPGUj
IV:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
CCCrypt(operation: 0x1, CCAlgorithm: 0x0, CCOptions: 0x1, keyBytes: 0x1657ddb8, keyLength: 0x10, ivBuffer: 0x1657fd80, inBuffer: 0x16577e90, inLength: 0x20, outBuffer: 0x1657f410, outLength: 0x30, outCountPtr: 0x154470)
Out buffer:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  4f 6d 65 64 20 63 72 79 70 74 20 64 65 63 72 79  Omed crypt decry
00000010  70 74 65 64                                      pted
Key:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  47 73 62 74 56 36 74 6f 50 55 66 56 50 47 55 6a  GsbtV6toPUfVPGUj
IV:
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```
