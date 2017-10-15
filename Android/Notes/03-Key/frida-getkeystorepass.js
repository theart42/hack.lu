if (Java.available) {
	Java.perform(function () {
		KeyStore = Java.use('java.security.KeyStore');
		KeyStore.load.overload('java.io.InputStream', '[C').implementation = function(stream, password) {
			if (password != null) {
				console.log("KeyStore loaded with password: " + password)
			}
			else {
				console.log("KeyStore loaded without password")
			}
			console.log("Stream: " + stream)
			return this.load(stream, password)
		}
	})
}