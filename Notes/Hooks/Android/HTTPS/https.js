if (Java.available) {
    Java.perform(function() {
        // const InputStreamReader = Java.use('java.io.InputStreamReader')
        clazz = 'com.android.okhttp.internal.huc.HttpURLConnectionImpl'
        const HttpURLConnection = Java.use(clazz)
        console.log('[+] Using class: ' + HttpURLConnection)
        console.log('[+] Handle "getInputStream": ' + HttpURLConnection.getInputStream.handle)

        // Here we will hook the implementation of the method getInputStream.
        // This method has NO overloads!
        HttpURLConnection.getInputStream.implementation = function() {
            console.log('[+] Inside "getInputStream" hook')

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
                    console.log(reader.readLine());
                }
            })
            // Pass the stream to the original caller.
            return stream
        }
    })
}