// 
// Copy all the readlines.
// 
if (Java.available) {
    Java.perform(function() {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function () {
            var line = this.readLine()
            if (line != null) {
                console.log(line)
            }
            return line
        }   
    })
}

// 
// Replace the message
// 
if (Java.available) {
    Java.perform(function() {
        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function () {
            line = this.readLine()
            console.log(line)
            if (line != null && line.match('participant')) {
                line = "Is this thing on?"
            }
            return line
        }   
    })
}