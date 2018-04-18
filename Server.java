import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Server{
	private enum CP {
		CLEARTEXT,
		CP1,
		CP2
	}
	/**
	 * @param args
	 */
	public static void main(String[] args) {

		System.out.print("Server is up with IP address: ");
		try {
			System.out.println(Inet4Address.getLocalHost().getHostAddress());
		} catch(Exception e) {
			System.out.println("Error getting IP address");
		}
		
		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			System.out.println("Establishing connection to client...");
			welcomeSocket = new ServerSocket(43211);

			connectionSocket = welcomeSocket.accept();
			System.out.println("Connection to client established");
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());
			System.out.println("Established connection to client...");
// START OF AUTHENTICATION PROTOCOL
			// Load CA cert
			InputStream fis = new FileInputStream("server.crt");
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert = (X509Certificate) cf.generateCertificate(fis);
			fis.close();
			
			// Load Private key
			byte[] privKeyByteArray = Files.readAllBytes(Paths.get("privateServer.der"));
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
			
			// Generate Symmetric key
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128);
			SecretKey mySymmKey = keyGen.generateKey();
			
			// Wait for client to initiate id req and send nonce
			
			
				if(fromClient.readUTF().equals(StringMessages.CLIENT_ID_REQ)) {
					int numBytes = fromClient.readInt();
					byte[] nonce = new byte[numBytes];
					fromClient.read(nonce);
					

					System.out.println("Received nonce");
					// Encrypt nonce with private key, and send message
					byte[] encryptedMessage = Crypto.encrypt(myPrivKey,nonce);

					System.out.println("Encrypted nonce");
					toClient.writeInt(encryptedMessage.length);

					System.out.println("Sent nonce length");
					toClient.flush();
					toClient.write(encryptedMessage);
					toClient.flush();
				} else {
					System.out.println("Connection terminated");
					return;
				}
			
			
			// 
			
			
			/*
			
			// Wait for client to initiate cert req
			for (BufferedReader br = new BufferedReader(new InputStreamReader(fromClient)); !connectionSocket.isClosed();) {
				if(br.readLine().equals(StringMessages.CLIENT_CERT_REQ)) {
					break;
				}
			}
			// Send cert to client
			toClient.write(CAcert.getEncoded());
			toClient.flush();
			*/
			// Wait for result of client check
			CP protocol = CP.CLEARTEXT;
			switch(fromClient.readUTF()) {
				case StringMessages.CLIENT_CP1_HANDSHAKE:
					protocol = CP.CP1;
					break;
				case StringMessages.CLIENT_CP2_HANDSHAKE:
					protocol = CP.CP2;
					// Send Encrypted Symm key for CP2
					byte[] encryptedMessage = Crypto.encrypt(myPrivKey,mySymmKey.getEncoded());
					toClient.writeInt(encryptedMessage.length);
					toClient.flush();
					toClient.write(encryptedMessage);
					toClient.flush();
					break;
				case StringMessages.CLIENT_END_REQ:
					fromClient.close();
					toClient.close();
					connectionSocket.close();
					return;
				default:
					fromClient.close();
					toClient.close();
					connectionSocket.close();
					return;
				}

			
			
				

			
// END OF AUTHENTICATION PROTOCOL
			int bCount = 0;
			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();
				
				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					
					byte [] filename = new byte[numBytes];
					fromClient.read(filename);
					

					fileOutputStream = new FileOutputStream(new String(filename, 0, numBytes));
					
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {
					bCount++;
					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.read(block);
					
					
					if (numBytes > 0){
						// Decrypt data block
						if (protocol == CP.CP1) {
							block = Crypto.decrypt(myPrivKey,block);
						} else if (protocol == CP.CP2) {
							block = Crypto.decrypt(mySymmKey,block);
						}
						bufferedFileOutputStream.write(block, 0, block.length);
					}
					
						
						
				} else if (packetType == 2) {
					System.out.println(bCount);
					System.out.println("Closing connection...");

					if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
					if (bufferedFileOutputStream != null) fileOutputStream.close();
					fromClient.close();
					toClient.close();
					connectionSocket.close();
					break;
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}


}
