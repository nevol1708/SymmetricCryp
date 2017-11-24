import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class SymmetricCryp {
	// thuật toán mã hóa
	private final String Algorithm = "AES";
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
		keyGen = KeyGenerator.getInstance(Algorithm);
		// 1.1 Sinh khóa đối xứng
		secretKey = keyGen.generateKey();
	}

	// 1.2 Tạo khóa đối xứng từ một chuỗi cho trước

	// 1.3 Mã hóa thông điệp có 2 tham số: Tham số 1 là chuỗi cần mã hóa, tham số
	// thứ 2 là khóa được tạo ở 1.1
	public String encryptText(String msg) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		cipher = Cipher.getInstance(Algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	// 1.4 Mã hóa thông điệp có 2 tham số: Tham số 1 là chuỗi cần mã hóa tham số 2
	// là khóa được tạo ở 1.2

	// 1.5 Giải mã có 2 tham số: Tham số 1 là bản mã, tham số thứ 2 là khóa bí mật
	// được tạo ở 1.1
	public String decryptText(String msg) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		cipher = Cipher.getInstance(Algorithm);
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
	}

	// 1.6 Giải mã có 2 tham số: Tham số 1 là bản mã, tham số thứ 2 là khóa bí mật
	// được tạo ở 1.2

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		SymmetricCryp SC = new SymmetricCryp();
		String msg = "Chuoi ma hoa";
		System.out.println("Plain text: " + msg);

		// 1.7 Sử dụng class SymetricCryp để mã hóa một chuỗi cho trước hoặc giải mã ra
		// bản rõ từ bản mã cho trước.
		String encrypted = SC.encryptText(msg);
		System.out.println("Encrypted text: " + encrypted);
		String decrypted = SC.decryptText(msg);
		System.out.println("Decrypted text: " + decrypted);
	}

}
