import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class SymmetricCryp {
	// khóa
	private SecretKey secretKey;
	// sinh khóa
	private KeyGenerator keyGen;
	// bộ mã
	private Cipher cipher;

	// get mã bí mật
	public SecretKey getSecretKey() {
		return secretKey;
	}

	// hàm tạo
	public SymmetricCryp() throws NoSuchAlgorithmException {
		// khởi tạo keygenerator
		keyGen = KeyGenerator.getInstance("AES");
		// khởi tạo khóa đối xứng
		secretKey = keyGen.generateKey();
	}

	// 1.1 Sinh khóa đối xứng
	public SecretKey generateKey() {
		return secretKey = keyGen.generateKey();
	}

	// 1.2 Tạo khóa đối xứng từ một chuỗi cho trước
	public SecretKey generateKey(String encodedKey) {
		byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		return originalKey;
	}
	public SecretKey generateKeyFromString(String input) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		byte[] inputKey = input.getBytes("UTF-8");
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		inputKey = sha.digest(inputKey);
		inputKey = Arrays.copyOf(inputKey, 16);	// Chỉ sử dụng 128 bit đầu tiên
		SecretKey originalKey = new SecretKeySpec(inputKey, 0, inputKey.length, "AES");
		return originalKey;
	}

	// 1.4 Mã hóa thông điệp có 2 tham số: Tham số 1 là chuỗi cần mã hóa tham số 2
	// là khóa được tạo ở 1.2
	public String encryptText(String msg, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	// 1.6 Giải mã có 2 tham số: Tham số 1 là bản mã, tham số thứ 2 là khóa bí mật
	// được tạo ở 1.2
	public String decryptText(String msg, SecretKey key) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
	}

	public static void main(String[] args) throws Exception {
		// 1.7 Sử dụng class SymetricCryp để mã hóa một chuỗi cho trước hoặc giải mã ra
		// bản rõ từ bản mã cho trước.
		SymmetricCryp SC = new SymmetricCryp();
		String msg = "Chuỗi cần mã hóa";
		System.out.println("Plain text: " + msg);
		String encodedKey = Base64.getEncoder().encodeToString(SC.getSecretKey().getEncoded());
		System.out.println("Khóa đối xứng được sinh: " + encodedKey);
		// 1.3 Mã hóa thông điệp có 2 tham số: Tham số 1 là chuỗi cần mã hóa, tham số
		// thứ 2 là khóa được tạo ở 1.1
		String encrypted = SC.encryptText(msg, SC.getSecretKey());
		System.out.println("Encrypted text: " + encrypted);
		// 1.5 Giải mã có 2 tham số: Tham số 1 là bản mã, tham số thứ 2 là khóa bí mật
		// được tạo ở 1.1
		String decrypted = SC.decryptText(encrypted, SC.getSecretKey());
		System.out.println("Decrypted text: " + decrypted);
		System.out.print("==================================\n");
		String newmsg = "Chuỗi thứ 2 cần mã hóa";
		System.out.println("Plain text: " + newmsg);
		// 1.2 Tạo khóa đối xứng từ một chuỗi cho trước ISt0DMalksQteZmDlRKj/g==
		SecretKey newKey = SC.generateKeyFromString("abc123");
		// 1.4 Mã hóa thông điệp có 2 tham số: Tham số 1 là chuỗi cần mã hóa tham số 2
		// là khóa được tạo ở 1.2
		String newencrypted = SC.encryptText(newmsg, newKey);
		System.out.println("Encrypted text: " + newencrypted);
		// 1.6 Giải mã có 2 tham số: Tham số 1 là bản mã, tham số thứ 2 là khóa bí mật
		// được tạo ở 1.2
		String newdecrypted = SC.decryptText(newencrypted, newKey);
		System.out.println("Decrypted text: " + newdecrypted);
	}

}
