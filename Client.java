import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client{

	public static void main(String[] args) {

    	String filename = "rr.txt";

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket("localhost", 43211);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			System.out.println("Established connection to server...");
			toServer.writeUTF(StringMessages.CLIENT_ID_REQ);
			toServer.flush();
			
			byte[] nonce = generateNonce();
			toServer.writeInt(nonce.length);
			toServer.flush();
			
			toServer.write(nonce);
			
			toServer.flush();
			System.out.println("Sent encrypted nonce");
			int storedInt = fromServer.readInt();

			byte[] storedByte = new byte[storedInt];
			fromServer.read(storedByte);
			System.out.println("Received encrypted nonce");
			// Load CA cert
			InputStream iS = new FileInputStream("server.crt");
			CertificateFactory cF = CertificateFactory.getInstance("X.509");
			X509Certificate CAcert = (X509Certificate) cF.generateCertificate(iS);
			iS.close();
			
			// Load public key from CA cert
			PublicKey myPubKey = CAcert.getPublicKey();
			
			byte[] decryptedMessage = Crypto.decrypt(myPubKey, storedByte);
			
			if (!Arrays.equals(nonce, decryptedMessage)){
		
				System.out.println("*"+new String(decryptedMessage)+"*");
				System.out.println("*"+new String(nonce)+"*");
				System.out.println(Arrays.toString(nonce));
				System.out.println(Arrays.toString(decryptedMessage));
				System.out.println(decryptedMessage.length);
				System.out.println(nonce.length);
				System.out.println(Arrays.equals(nonce, decryptedMessage));
				toServer.writeUTF(StringMessages.CLIENT_END_REQ);
				toServer.flush();
				return;
			}
		
			
			System.out.println("Sending file...");
			
/*			
			toServer.writeUTF(StringMessages.CLIENT_CP1_HANDSHAKE);
			toServer.flush();
			
			toServer.writeInt(0);
			toServer.flush();
			toServer.writeInt(filename.getBytes().length);
			toServer.flush();
			toServer.write(filename.getBytes());
			toServer.flush();
			
			System.out.println("sent");
			System.out.println(filename.getBytes().length);
			*/
			Scanner reader = new Scanner(System.in);
			System.out.println("Enter 1 or 2");
			int n = reader.nextInt();
			

			if ( n == 1 ){
				toServer.writeUTF(StringMessages.CLIENT_CP1_HANDSHAKE);
				toServer.flush();
				
				// Send the filename
				toServer.writeInt(0);
				toServer.flush();
				toServer.writeInt(filename.getBytes().length);
				toServer.flush();
				toServer.write(filename.getBytes());
				toServer.flush();
				

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);
				
				System.out.println(fileInputStream.toString().length());
						
				final int FILE_BUFFER_LEN = 50;
		        byte [] fromFileBuffer = new byte[FILE_BUFFER_LEN];
				System.out.println("hey");
				
				boolean isTrue = true;
				int bCount = 0;
				while(isTrue){
					for(int off=0; ;off+=FILE_BUFFER_LEN){
						{
							if(bufferedFileInputStream.read(fromFileBuffer, 0, FILE_BUFFER_LEN)==-1){
								isTrue = false;
								
								break;
							} else {
								// Do something with fromFileBuffer, like encrypt it and send it over
								byte[] encryptTheFile = Crypto.encrypt(myPubKey, fromFileBuffer);
								toServer.writeInt(1);
								toServer.flush();
						        toServer.writeInt(encryptTheFile.length);
								toServer.flush();
								toServer.write(encryptTheFile);
								toServer.flush();
								bCount++;
							}
						}
					}

				}
				System.out.println(bCount);
		        bufferedFileInputStream.close();
		        fileInputStream.close();
		        reader.close();
				
			}
			else if (n==2){
				toServer.writeUTF(StringMessages.CLIENT_CP2_HANDSHAKE);
				toServer.flush();
				
				// Get symmetric key
				int storedInt2 = fromServer.readInt();
				byte[] storedByte2 = new byte[storedInt2];
				fromServer.read(storedByte2);
				storedByte2 = Crypto.decrypt(myPubKey, storedByte2);
				SecretKey originalKey = new SecretKeySpec(storedByte2, 0 , storedByte2.length, "AES");
				

				
				// Send the filename
				toServer.writeInt(0);
				toServer.flush();
				toServer.writeInt(filename.getBytes().length);
				toServer.flush();
				toServer.write(filename.getBytes());
				toServer.flush();

				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);
				
				System.out.println(fileInputStream.toString().length());
				
				final int FILE_BUFFER_LEN = 300;
		        byte [] fromFileBuffer = new byte[FILE_BUFFER_LEN];
				
		        
		        boolean isTrue = true;
		        
		        while(isTrue){
		        	for(int off=0;;off+=FILE_BUFFER_LEN){

		        			if(bufferedFileInputStream.read(fromFileBuffer, 0, FILE_BUFFER_LEN)==-1){
		        				isTrue = false;
		        				
								break;
							} else {
								byte[] encryptTheFile2 = Crypto.encrypt(originalKey, fromFileBuffer);
								
								toServer.writeInt(1);
								toServer.flush();
						        toServer.writeInt(encryptTheFile2.length);
								toServer.flush();
								toServer.write(encryptTheFile2);
								toServer.flush();
								
							}

		        	}

		        }
								
				

				
			}
			
			System.out.println("Closing connection...");
	        toServer.writeInt(2);
	        toServer.flush();
	        
	        

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
		try{
        	TimeUnit.SECONDS.sleep(15);
        } catch(Exception e){
        	
        }
		
	}
	static byte[] generateNonce() {
		// TODO: Generate a nonce
		byte[] longByte = new byte[117];
		new Random().nextBytes(longByte);
		
		return longByte;
	}
	
	
}
