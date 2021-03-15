package comsang.config;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.UUID;

/**
 * Created by wwb
 * 2020/6/8
 * email: wangweibin@zkzz.onaliyun.com
 * <p>
 * need jars:
 * bcprov-jdk15on-165.jar
 * <p>
 * ref:
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 * http://gmssl.org/docs/oid.html
 * http://www.jonllen.com/jonllen/work/164.aspx
 * https://blog.csdn.net/pridas/article/details/86118774
 * <p>
 * 用BC的注意点：
 * 这个版本的BC对SM3withSM2的结果为asn1格式的r和s，如果需要直接拼接的r||s需要自己转换。下面rsAsn1ToPlainByteArray、rsPlainByteArrayToAsn1就在干这事。
 * 这个版本的BC对SM2的结果为C1||C2||C3，据说为旧标准，新标准为C1||C3||C2，用新标准的需要自己转换。下面changeC1C2C3ToC1C3C2、changeC1C3C2ToC1C2C3就在干这事。
 */
public class GMUtil {

    private final static int X_Y_LEN = 64;
    private final static int PRIVATE_KEY_LEN = 64;
    private final static int RS_LEN = 32;
    private static final X9ECParameters x9ECParameters = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters ecDomainParameters = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());
    private static final ECParameterSpec ecParameterSpec = new ECParameterSpec(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN());

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

    /**
     * @param msg
     * @param userId
     * @param privateKey
     * @return r||s，直接拼接byte数组的rs
     */
    public static byte[] signSm3WithSm2(final byte[] msg, final byte[] userId, final PrivateKey privateKey) {
        return rsAsn1ToPlainByteArray(signSm3WithSm2Asn1Rs(msg, userId, privateKey));
    }

    /**
     * @param msg
     * @param userId
     * @param privateKey
     * @return rs in <b>asn1 format</b>
     */
    public static byte[] signSm3WithSm2Asn1Rs(final byte[] msg, final byte[] userId, final PrivateKey privateKey) {
        try {
            final SM2ParameterSpec parameterSpec = new SM2ParameterSpec(userId);
            final Signature signer = Signature.getInstance("SM3withSM2", "BC");
            signer.setParameter(parameterSpec);
            signer.initSign(privateKey, new SecureRandom());
            signer.update(msg, 0, msg.length);
            final byte[] sig = signer.sign();
            return sig;
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @param msg
     * @param userId
     * @param rs        r||s，直接拼接byte数组的rs
     * @param publicKey
     * @return
     */
    public static boolean verifySm3WithSm2(final byte[] msg, final byte[] userId, final byte[] rs, final PublicKey publicKey) {
        return verifySm3WithSm2Asn1Rs(msg, userId, rsPlainByteArrayToAsn1(rs), publicKey);
    }

    /**
     * @param msg
     * @param userId
     * @param rs        in <b>asn1 format</b>
     * @param publicKey
     * @return
     */
    public static boolean verifySm3WithSm2Asn1Rs(final byte[] msg, final byte[] userId, final byte[] rs, final PublicKey publicKey) {
        try {
            final SM2ParameterSpec parameterSpec = new SM2ParameterSpec(userId);
            final Signature verifier = Signature.getInstance("SM3withSM2", "BC");
            verifier.setParameter(parameterSpec);
            verifier.initVerify(publicKey);
            verifier.update(msg, 0, msg.length);
            return verifier.verify(rs);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * bc加解密使用旧标c1||c2||c3，此方法在加密后调用，将结果转化为c1||c3||c2
     *
     * @param c1c2c3
     * @return
     */
    private static byte[] changeC1C2C3ToC1C3C2(final byte[] c1c2c3) {
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c3Len = 32; //new SM3Digest().getDigestSize();
        final byte[] result = new byte[c1c2c3.length];
        System.arraycopy(c1c2c3, 0, result, 0, c1Len); //c1
        System.arraycopy(c1c2c3, c1c2c3.length - c3Len, result, c1Len, c3Len); //c3
        System.arraycopy(c1c2c3, c1Len, result, c1Len + c3Len, c1c2c3.length - c1Len - c3Len); //c2
        return result;
    }

    /**
     * bc加解密使用旧标c1||c3||c2，此方法在解密前调用，将密文转化为c1||c2||c3再去解密
     *
     * @param c1c3c2
     * @return
     */
    private static byte[] changeC1C3C2ToC1C2C3(final byte[] c1c3c2) {
        final int c1Len = (x9ECParameters.getCurve().getFieldSize() + 7) / 8 * 2 + 1; //sm2p256v1的这个固定65。可看GMNamedCurves、ECCurve代码。
        final int c3Len = 32; //new SM3Digest().getDigestSize();
        final byte[] result = new byte[c1c3c2.length];
        System.arraycopy(c1c3c2, 0, result, 0, c1Len); //c1: 0->65
        System.arraycopy(c1c3c2, c1Len + c3Len, result, c1Len, c1c3c2.length - c1Len - c3Len); //c2
        System.arraycopy(c1c3c2, c1Len, result, c1c3c2.length - c3Len, c3Len); //c3
        return result;
    }

    /**
     * c1||c3||c2
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2Decrypt(final byte[] data, final PrivateKey key) {
        return sm2DecryptOld(changeC1C3C2ToC1C2C3(data), key);
    }

    /**
     * c1||c3||c2
     *
     * @param data
     * @param key
     * @return
     */

    public static byte[] sm2Encrypt(final byte[] data, final PublicKey key) {
        return changeC1C2C3ToC1C3C2(sm2EncryptOld(data, key));
    }

    /**
     * c1||c2||c3
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2EncryptOld(final byte[] data, final PublicKey key) {
        final BCECPublicKey localECPublicKey = (BCECPublicKey) key;
        final ECPublicKeyParameters ecPublicKeyParameters = new ECPublicKeyParameters(localECPublicKey.getQ(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(true, new ParametersWithRandom(ecPublicKeyParameters, new SecureRandom()));
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (final InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * c1||c2||c3
     *
     * @param data
     * @param key
     * @return
     */
    public static byte[] sm2DecryptOld(final byte[] data, final PrivateKey key) {
        final BCECPrivateKey localECPrivateKey = (BCECPrivateKey) key;
        final ECPrivateKeyParameters ecPrivateKeyParameters = new ECPrivateKeyParameters(localECPrivateKey.getD(), ecDomainParameters);
        final SM2Engine sm2Engine = new SM2Engine();
        sm2Engine.init(false, ecPrivateKeyParameters);
        try {
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (final InvalidCipherTextException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sm4Encrypt(final byte[] keyBytes, final byte[] plain) {
        if (keyBytes.length != 16) {
            throw new RuntimeException("err key length");
        }
        if (plain.length % 16 != 0) {
            throw new RuntimeException("err data length");
        }

        try {
            final Key key = new SecretKeySpec(keyBytes, "SM4");
            final Cipher out = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
            out.init(Cipher.ENCRYPT_MODE, key);
            return out.doFinal(plain);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sm4Decrypt(final byte[] keyBytes, final byte[] cipher) {
        if (keyBytes.length != 16) {
            throw new RuntimeException("err key length");
        }
        if (cipher.length % 16 != 0) {
            throw new RuntimeException("err data length");
        }

        try {
            final Key key = new SecretKeySpec(keyBytes, "SM4");
            final Cipher in = Cipher.getInstance("SM4/ECB/NoPadding", "BC");
            in.init(Cipher.DECRYPT_MODE, key);
            return in.doFinal(cipher);

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static SM4ECBCipher sm4EncryptWithECB(final byte[] keyBytes, final byte[] plain) {
        int offset = 0;
        final byte[] cipher;
        if (plain.length % 16 != 0) {
            offset = 16 - (plain.length % 16);
//            System.out.println("SM4ECBCipher offset:" + offset);
            final byte[] paddedPlain = new byte[offset + plain.length];
//            byte[] offsetBytes = new byte[offset];
            System.arraycopy(new byte[offset], 0, paddedPlain, 0, offset);
            System.arraycopy(plain, 0, paddedPlain, offset, plain.length);

//            System.out.println(paddedPlain.length);
//            System.out.println(new String(paddedPlain));

            cipher = sm4Encrypt(keyBytes, paddedPlain);
        } else {
            cipher = sm4Encrypt(keyBytes, plain);
        }

        return new SM4ECBCipher(offset, cipher);
    }

    /**
     * @param bytes
     * @return
     */
    public static byte[] sm3(final byte[] bytes) {
        final SM3Digest sm3 = new SM3Digest();
        sm3.reset();
        sm3.update(bytes, 0, bytes.length);
        final byte[] result = new byte[sm3.getDigestSize()];
        sm3.doFinal(result, 0);
        return result;
    }

    private static byte[] bigIntToFixexLengthBytes(final BigInteger rOrS) {
        // for sm2p256v1, n is 00fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
        // r and s are the result of mod n, so they should be less than n and have length<=32
        final byte[] rs = rOrS.toByteArray();
        if (rs.length == RS_LEN) {
            return rs;
        } else if (rs.length == RS_LEN + 1 && rs[0] == 0) {
            return Arrays.copyOfRange(rs, 1, RS_LEN + 1);
        } else if (rs.length < RS_LEN) {
            final byte[] result = new byte[RS_LEN];
            Arrays.fill(result, (byte) 0);
            System.arraycopy(rs, 0, result, RS_LEN - rs.length, rs.length);
            return result;
        } else {
            throw new RuntimeException("err rs: " + Hex.toHexString(rs));
        }
    }

    /**
     * BC的SM3withSM2签名得到的结果的rs是asn1格式的，这个方法转化成直接拼接r||s
     *
     * @param rsDer rs in asn1 format
     * @return sign result in plain byte array
     */
    private static byte[] rsAsn1ToPlainByteArray(final byte[] rsDer) {
        final ASN1Sequence seq = ASN1Sequence.getInstance(rsDer);
        final byte[] r = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        final byte[] s = bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        final byte[] result = new byte[RS_LEN * 2];
        System.arraycopy(r, 0, result, 0, r.length);
        System.arraycopy(s, 0, result, RS_LEN, s.length);
        return result;
    }

    /**
     * BC的SM3withSM2验签需要的rs是asn1格式的，这个方法将直接拼接r||s的字节数组转化成asn1格式
     *
     * @param sign in plain byte array
     * @return rs result in asn1 format
     */
    private static byte[] rsPlainByteArrayToAsn1(final byte[] sign) {
        if (sign.length != RS_LEN * 2) {
            throw new RuntimeException("err rs. ");
        }
        final BigInteger r = new BigInteger(1, Arrays.copyOfRange(sign, 0, RS_LEN));
        final BigInteger s = new BigInteger(1, Arrays.copyOfRange(sign, RS_LEN, RS_LEN * 2));
        final ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(r));
        v.add(new ASN1Integer(s));
        try {
            return new DERSequence(v).getEncoded("DER");
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 补全十六进制字符串，往字符串开头补0
     *
     * @param input  十六进制字符串
     * @param length 应有的字符串长度
     * @return 补全长度后的十六进制字符串
     */
    private static String leftPadString(String input, final int length) {
        if (input.length() < length) {
            final int delta = length - input.length();
            final StringBuilder inputBuilder = new StringBuilder(input);
            for (int i = 0; i < delta; i++) {
                inputBuilder.insert(0, "0");
            }
            input = inputBuilder.toString();
        }
        return input;
    }

    public static KeyPair generateKeyPair() {
        try {
            final KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");
            kpGen.initialize(ecParameterSpec, new SecureRandom());
            return kpGen.generateKeyPair();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getPrivateKeyHex(final PrivateKey privateKey) {
        String privateKeyHex = ((BCECPrivateKey) privateKey).getD().toString(16);
        privateKeyHex = leftPadString(privateKeyHex, 64);
        return privateKeyHex;

    }

    public static String getPublicKeyHex(final PublicKey publicKey) {
        final String X = leftPadString("" + ((BCECPublicKey) publicKey).getQ().getXCoord(), 64);
        final String Y = leftPadString("" + ((BCECPublicKey) publicKey).getQ().getYCoord(), 64);
        return "04" + X + Y;
    }

    public static BCECPrivateKey getPrivateKeyFromHex(final String hex) {
        if (hex.length() != PRIVATE_KEY_LEN) {
            throw new RuntimeException("wrong private key hex length.");
        }
        final BigInteger d = new BigInteger(hex, 16);
        return getPrivateKeyFromD(d);
    }

    public static BCECPrivateKey getPrivateKeyFromD(final BigInteger d) {
        final ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(d, ecParameterSpec);
        return new BCECPrivateKey("EC", ecPrivateKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    /**
     * 从十六进制的字符串中获取公钥，一般该格式的公钥以04开头
     *
     * @param hex 04 + X + Y
     * @return BCECPublicKey
     */
    public static BCECPublicKey getPublicKeyFromHex(final String hex) {
        if (hex.length() != X_Y_LEN * 2 + 2) {
            throw new RuntimeException("wrong public key hex length.");
        }
        final BigInteger X = new BigInteger(hex.substring(2, 66), 16);
        final BigInteger Y = new BigInteger(hex.substring(66), 16);
        return getPublicKeyFromXY(X, Y);
    }

    public static BCECPublicKey getPublicKeyFromXY(final BigInteger x, final BigInteger y) {
        final ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(x9ECParameters.getCurve().createPoint(x, y), ecParameterSpec);
        return new BCECPublicKey("EC", ecPublicKeySpec, BouncyCastleProvider.CONFIGURATION);
    }

    public static PublicKey getPublicKeyFromX509File(final File file) {
        try {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            final FileInputStream in = new FileInputStream(file);
            final X509Certificate x509 = (X509Certificate) cf.generateCertificate(in);
//            System.out.println(x509.getSerialNumber());
            return x509.getPublicKey();
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(final String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, CertPathBuilderException, InvalidKeyException, SignatureException, CertificateException {

        String s = UUID.randomUUID().toString();
        s = s.substring(0, 8) + s.substring(9, 13) + s.substring(14, 18);
        System.out.println(s.length());
        System.out.println(s);
        // sm4 test ---------------------
        final byte[] plain = "需要SM4加密的密文内容".getBytes();
        final byte[] key = "0123456789abcdef".getBytes();     // 密钥长度为16字节

        // SM4 加密
        final SM4ECBCipher sm4ECBCipher = sm4EncryptWithECB(key, plain);      // 分组对称加密，plain长度不足16的倍数的会在plain的前补0，再进行分组加密
        final String sm4ECBCipherHexString = sm4ECBCipher.toHexString();
        // 密文
        // sm4分组加密密文的十六进制字符串。
        // 字符串中，第一个字符为十六进制的offset大小，解密时需提出offset，对后面的密文用密钥解密。
        // 得出的byte[]再去掉开始的offset个byte，得到的就是原文
        System.out.println("SM4 密文（带offset大小）: " + sm4ECBCipherHexString);
//        System.out.println("SM4 密文: " + Hex.toHexString(sm4ECBCipher.cipher));

        // SM4 解密
        final SM4ECBCipher cipherToDecrypt = new SM4ECBCipher(sm4ECBCipherHexString);
        byte[] bs = cipherToDecrypt.decrypt(key);
        // 原文
        String decrypted = new String(bs);
        System.out.println("SM4 解密获得的原文: " + decrypted);

        if (!decrypted.equals(new String(plain))) {
            throw new RuntimeException("解密获得的原文不一致!");
        }

        // sm3 test ------------------
        final byte[] hash = sm3("需要SM3的内容".getBytes());
        System.out.println("SM3 hash: " + Hex.toHexString(hash));


        // sm2 test --------------
        // 生成密钥对
        final KeyPair keyPair = generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();

        // 将密钥转成十六进制字符串
        final String privateKeyHex = getPrivateKeyHex(privateKey);
        final String publicKeyHex = getPublicKeyHex(publicKey);

        System.out.println("privateKeyHex: " + privateKeyHex);
        System.out.println("publicKeyHex: " + publicKeyHex);

        // 从十六进制字符串提出密钥
        final PrivateKey privateKey1 = getPrivateKeyFromHex(privateKeyHex);
        final PublicKey publicKey1 = getPublicKeyFromHex(publicKeyHex);

        System.out.println("privateKey.equals(privateKey1): " + privateKey.equals(privateKey1));
        System.out.println("publicKey.equals(publicKey1): " + publicKey.equals(publicKey1));

        if (!privateKey.equals(privateKey1) || !publicKey.equals(publicKey1)) {
            throw new RuntimeException("key not equals!");
        }

        // SM2 用公钥 加密
        final String str = "需要加密的内容";
        bs = sm2Encrypt(str.getBytes(), publicKey);
        System.out.println("SM2 密文：" + Hex.toHexString(bs));

        // SM2 用私钥 解密
        bs = sm2Decrypt(bs, privateKey);
        decrypted = new String(bs);
        System.out.println("SM2 解密获得的原文：" + decrypted);

        if (!decrypted.equals(str)) {
            throw new RuntimeException("decrypted not equals!");
        }

        // SM2 用私钥 签名
        final byte[] msg = "需要签名的内容".getBytes();   // 需要签名的内容
        final byte[] userId = "userId_001".getBytes();        // 签名人的userId
        final byte[] sig = signSm3WithSm2(msg, userId, privateKey);   // 得到的SM2签名
        System.out.println("签名：" + Hex.toHexString(sig));
        // SM2 用公钥 验签
        final boolean verified = verifySm3WithSm2(msg, userId, sig, publicKey);   // 验签结果
        System.out.println("签名验证结果：" + verified);

        if (!verified) {
            throw new RuntimeException("签名验证错误!");
        }


//        // 随便看看 ---------------------
//        System.out.println("GMNamedCurves: ");
//        for(Enumeration e = GMNamedCurves.getNames(); e.hasMoreElements();) {
//            System.out.println(e.nextElement());
//        }
//        System.out.println("sm2p256v1 n:"+x9ECParameters.getN());
//        System.out.println("sm2p256v1 nHex:"+Hex.toHexString(x9ECParameters.getN().toByteArray()));


        // 生成公私钥对 ---------------------
//        KeyPair kp = generateKeyPair();
//
//        System.out.println(Hex.toHexString(kp.getPrivate().getEncoded()));
//        System.out.println(Hex.toHexString(kp.getPublic().getEncoded()));
//
//        System.out.println(kp.getPrivate().getAlgorithm());
//        System.out.println(kp.getPublic().getAlgorithm());
//
//        System.out.println(kp.getPrivate().getFormat());
//        System.out.println(kp.getPublic().getFormat());
//
//        BigInteger privateKeyD = ((BCECPrivateKey) kp.getPrivate()).getD();
//        System.out.println("private key d (bigInteger): " + privateKeyD);
//        System.out.println("private key d hex: "+ privateKeyD.toString(16));
//        System.out.println("public key q: " + ((BCECPublicKey) kp.getPublic()).getQ()); //{x, y, zs...}
//
//        System.out.println("public key hex: " + "04" + (((BCECPublicKey) kp.getPublic()).getQ().getXCoord())+((BCECPublicKey) kp.getPublic()).getQ().getYCoord());
//
//        byte[] msg = "message digest".getBytes();
//        byte[] userId = "userId".getBytes();
//        byte[] sig = signSm3WithSm2(msg, userId, kp.getPrivate());
//        System.out.println(Hex.toHexString(sig));
//        System.out.println(verifySm3WithSm2(msg, userId, sig, kp.getPublic()));


//        // 由d生成私钥 ---------------------
//        BigInteger d = new BigInteger("d5b5ae75c41ad0dfc0319d85fe50a853517f1c220c34e9817b608c46b97ffc46", 16);
//        BCECPrivateKey bcecPrivateKey = getPrivatekeyFromD(d);
//
//        System.out.println(bcecPrivateKey.getParameters());
//        System.out.println(Hex.toHexString(bcecPrivateKey.getEncoded()));
//        System.out.println(bcecPrivateKey.getAlgorithm());
//        System.out.println(bcecPrivateKey.getFormat());
//        System.out.println(bcecPrivateKey.getD());
//        System.out.println(bcecPrivateKey instanceof java.security.interfaces.ECPrivateKey);
//        System.out.println(bcecPrivateKey instanceof ECPrivateKey);
//        System.out.println(bcecPrivateKey.getParameters());


//        公钥X坐标PublicKeyXHex: 59cf9940ea0809a97b1cbffbb3e9d96d0fe842c1335418280bfc51dd4e08a5d4
//        公钥Y坐标PublicKeyYHex: 9a7f77c578644050e09a9adc4245d1e6eba97554bc8ffd4fe15a78f37f891ff8
//        PublicKey publicKey = getPublickeyFromX509File(new File("/Users/xxx/Downloads/xxxxx.cer"));
//        System.out.println(publicKey);
//        PublicKey publicKey1 = getPublickeyFromXY(new BigInteger("b699c5eafc50b55d76feb03ba5b8223aa6b1ec99b9c0d16c72cc0419faf0ab94", 16), new BigInteger("53511a145c01368458cefb36e1eda4c6409e18275bb668044a5a363a183e7f3c", 16));
//        System.out.println(publicKey1);
//        System.out.println(publicKey.equals(publicKey1));
//        System.out.println(publicKey.getEncoded().equals(publicKey1.getEncoded()));


//        // sm2 encrypt and decrypt test ---------------------
//        KeyPair kp = generateKeyPair();
//
//        PublicKey publicKey2 = kp.getPublic();
//        PrivateKey privateKey2 = kp.getPrivate();
//
//        System.out.println(((BCECPrivateKey) kp.getPrivate()).getD());
//        System.out.println(((BCECPrivateKey) kp.getPrivate()).getFormat());
//
//        byte[]bs = sm2Encrypt("需要加密的内容".getBytes(), publicKey1);
//        System.out.println(Hex.toHexString(bs));
//        bs = sm2Decrypt(bs, bcecPrivateKey);
//        System.out.println(new String(bs));
    }

    /**
     * SM4分组加密结果
     */
    public static class SM4ECBCipher {
        int offset;
        byte[] cipher;

        public SM4ECBCipher(final int offset, final byte[] cipher) {
            this.offset = offset;
            this.cipher = cipher;
        }

        /**
         * 从带offset的十六进制字符串密文中得到SM4ECBCipher
         *
         * @param hexStr 带offset的十六进制字符串密文
         */
        public SM4ECBCipher(final String hexStr) {
            this.offset = Integer.parseInt(hexStr.substring(0, 1), 16);
            this.cipher = Hex.decode(hexStr.substring(1));
        }

        public int getOffset() {
            return this.offset;
        }

        public void setOffset(final int offset) {
            this.offset = offset;
        }

        public byte[] getCipher() {
            return this.cipher;
        }

        public void setCipher(final byte[] cipher) {
            this.cipher = cipher;
        }

        @Override
        public String toString() {
            return "SM4ECBCipher{" +
                    "offset=" + this.offset +
                    ", cipher=" + Arrays.toString(this.cipher) +
                    '}';
        }

        public String toHexString() {
            return Integer.toHexString(this.offset) + Hex.toHexString(this.cipher);
        }

        public byte[] decrypt(final byte[] keyBytes) {
            final byte[] decryptedWithOffset = GMUtil.sm4Decrypt(keyBytes, this.cipher);
            return Arrays.copyOfRange(decryptedWithOffset, this.offset, decryptedWithOffset.length);
        }
    }
}
