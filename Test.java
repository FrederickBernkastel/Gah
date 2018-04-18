import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Locale;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Test{
	public static void main(String[] arg) {
// Test der/crt RSA encryption and decryption
		try {
			// Load CA cert
			InputStream fis = new FileInputStream("server.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);
			fis.close();
			
			// Load public key from CA cert
			PublicKey myPubKey = CAcert.getPublicKey();
			
			// Load Private key
			byte[] privKeyByteArray = Files.readAllBytes(Paths.get("privateServer.der"));
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
			
			// Load Test message
			final String msg = "Test Message!";
			byte[] output = Crypto.decrypt(myPrivKey, Crypto.encrypt(myPubKey, msg));
			if (!new String(output).equals(msg)){
				throw new Exception("RSA encyption / decryption test failed");
			}
			System.out.println("RSA Test passed");
			
// Test Symmetric encryption/decryption
			// Generate Symmetric key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey mySymmKey = keyGen.generateKey();
			
			// Load Test message
			byte[] symmKey = mySymmKey.getEncoded();
			symmKey = Crypto.encrypt(myPubKey, symmKey);
			symmKey = Crypto.decrypt(myPrivKey, symmKey);
			output = Crypto.decrypt(
					mySymmKey, 
					Crypto.encrypt(
							new SecretKeySpec(
									symmKey, 
									0 , 
									symmKey.length,
									"AES"), 
							msg));
			if (!new String(output).equals(msg)){
				throw new Exception("RSA encyption / decryption test failed");
			}
			System.out.println("Symm Test passed");
// Test Nonce generation
			if(new String(Client.generateNonce()).equals(new String(Client.generateNonce()))) {
				throw new Exception("Nonce generation failed");
			}
			System.out.println("Nonce test passed");
			
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
	}
}