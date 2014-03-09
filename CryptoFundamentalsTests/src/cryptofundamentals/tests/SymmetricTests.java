package cryptofundamentals.tests;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class SymmetricTests {
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void generateARandomAesKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(256);
		SecretKey key = keyGenerator.generateKey();

		assertEquals("AES", key.getAlgorithm());
		assertEquals(32, key.getEncoded().length);
	}

	@Test
	public void encryptAMessageWithAes() throws Exception {
		String message = "Alice knows Bob's secret.";

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
		keyGenerator.init(256);
		SecretKey key = keyGenerator.generateKey();
		
		SecureRandom random = new SecureRandom();
		byte[] buffer = new byte[16];
		random.nextBytes(buffer);
		IvParameterSpec iv = new IvParameterSpec(buffer);
		
		byte[] cipertext = encryptWithAes(message, key, iv);
		String actualMessage = decryptWithAes(cipertext, key, iv);
		
		assertEquals(message, actualMessage);
	}

	private byte[] encryptWithAes(String message, SecretKey key, IvParameterSpec iv)
		throws Exception {
		
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aes.init(Cipher.ENCRYPT_MODE, key, iv);
		CipherOutputStream cipherOut = new CipherOutputStream(out, aes);
		OutputStreamWriter writer = new OutputStreamWriter(cipherOut);
		
		try {
			writer.write(message);
		}
		finally {
			writer.close();
		}
		
		return out.toByteArray();
	}

	private String decryptWithAes(byte[] cipertext, SecretKey key, IvParameterSpec iv)
		throws Exception {

		ByteArrayInputStream in = new ByteArrayInputStream(cipertext);
		Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
		aes.init(Cipher.DECRYPT_MODE, key, iv);
		CipherInputStream cipherIn = new CipherInputStream(in, aes);
		InputStreamReader reader = new InputStreamReader(cipherIn);
		BufferedReader bufferedReader = new BufferedReader(reader);
		
		try {
			return bufferedReader.readLine();
		}
		finally {
			bufferedReader.close();
		}
	}
	
	/*
	Every implementation of the Java platform is required to support the following standard Cipher transformations with the keysizes in parentheses:
	AES/CBC/NoPadding (128)
	AES/CBC/PKCS5Padding (128)
	AES/ECB/NoPadding (128)
	AES/ECB/PKCS5Padding (128)
	DES/CBC/NoPadding (56)
	DES/CBC/PKCS5Padding (56)
	DES/ECB/NoPadding (56)
	DES/ECB/PKCS5Padding (56)
	DESede/CBC/NoPadding (168)
	DESede/CBC/PKCS5Padding (168)
	DESede/ECB/NoPadding (168)
	DESede/ECB/PKCS5Padding (168)
	RSA/ECB/PKCS1Padding (1024, 2048)
	RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
	RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
	 */
}
