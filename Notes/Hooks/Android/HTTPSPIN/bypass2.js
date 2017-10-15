if (Java.available) {
	Java.perform(function () {
		TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
		TrustManagerFactory.init.overload('java.security.KeyStore').implementation = function(keystore) {
			console.log("Overwriting keystore to null")
			return this.init(null);
		}
	})
}