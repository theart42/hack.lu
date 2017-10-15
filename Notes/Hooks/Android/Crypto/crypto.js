if (Java.available) {
	Java.perform(function () {
		String = Java.use("java.lang.String")

		SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
		SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, type) {
			console.log("[+] Key: " + key)
			console.log("[+] Type: " + type)
			return this.$init(key,type)
		}

		Cipher = Java.use('javax.crypto.Cipher')
		Cipher.doFinal.overload('[B').implementation = function(bytes) {
			s = String.$new(bytes, "UTF-8")
			console.log("[+] Data: " + s)
			return this.doFinal(bytes)	
		}
	});
}