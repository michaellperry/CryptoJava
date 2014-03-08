package cryptofundamentals.tests;

import static org.junit.Assert.*;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.Test;

public class AsymmetricTests {

	@Test
	public void generateAnRsaKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		assertEquals("RSA", keyPair.getPublic().getAlgorithm());
		assertTrue(keyPair.getPublic().getEncoded().length > 2048 / 8);
		assertTrue(keyPair.getPrivate().getEncoded().length > 2048 / 8);
	}
	
	@Test
	public void encryptASymmetricKey() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		SecretKey key = keyGenerator.generateKey();
		
		byte[] encryptedKey = encryptWithRsa(publicKey, key);
		byte[] decryptedKey = decryptWithRsa(privateKey, encryptedKey);
		
		assertArrayEquals(key.getEncoded(), decryptedKey);
	}
	
	@Test
	public void signeAMessage() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		String message = "Alice knows Bob's secret.";
		byte[] messageBytes = message.getBytes();
		
		byte[] signatureBytes = signMessage(privateKey, messageBytes);
		boolean verified = verifySignature(publicKey, messageBytes, signatureBytes);
		
		assertTrue(verified);
	}

	private byte[] encryptWithRsa(PublicKey publicKey, SecretKey key)
			throws Exception {
		
		Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		rsa.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedKey = rsa.doFinal(key.getEncoded());
		return encryptedKey;
	}

	private byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedKey)
			throws Exception {
		
		Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		rsa.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedKey = rsa.doFinal(encryptedKey);
		return decryptedKey;
	}

	private byte[] signMessage(PrivateKey privateKey, byte[] messageBytes)
			throws Exception {
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(messageBytes);
		return signature.sign();
	}

	private boolean verifySignature(PublicKey publicKey, byte[] messageBytes,
			byte[] signatureBytes) throws Exception {
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(messageBytes);
		return signature.verify(signatureBytes);
	}

}
