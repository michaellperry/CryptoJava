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
		KeyPair keyPair = generateRsaKey();
		
		assertEquals("RSA", keyPair.getPublic().getAlgorithm());
		assertTrue(keyPair.getPublic().getEncoded().length > 2048 / 8);
		assertTrue(keyPair.getPrivate().getEncoded().length > 2048 / 8);
	}
	
	@Test
	public void encryptASymmetricKey() throws Exception {
		KeyPair keyPair = generateRsaKey();

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
	public void signAMessage() throws Exception {
		KeyPair keyPair = generateRsaKey();

		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		String message = "Alice knows Bob's secret.";
		byte[] messageBytes = message.getBytes();
		
		byte[] signatureBytes = signMessage(privateKey, messageBytes);
		boolean verified = verifySignature(publicKey, messageBytes, signatureBytes);
		
		assertTrue(verified);
	}

	private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
		return null;
	}

	private byte[] encryptWithRsa(PublicKey publicKey, SecretKey key)
			throws Exception {
		
		Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		return null;
	}

	private byte[] decryptWithRsa(PrivateKey privateKey, byte[] encryptedKey)
			throws Exception {
		
		Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
		return rsa.doFinal(encryptedKey);
	}

	private byte[] signMessage(PrivateKey privateKey, byte[] messageBytes)
			throws Exception {
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		return signature.sign();
	}

	private boolean verifySignature(PublicKey publicKey, byte[] messageBytes,
			byte[] signatureBytes) throws Exception {
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		return signature.verify(signatureBytes);
	}

}
