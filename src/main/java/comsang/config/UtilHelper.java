package comsang.config;


import org.apache.tomcat.util.codec.binary.Base64;

public class UtilHelper {


    /**
     * base64字符串转byte[]
     */
    public static byte[] base64String2ByteFun(final String base64Str) {
        return Base64.decodeBase64(base64Str);
    }

    /**
     * byte[]转base64
     *
     * @param b
     * @return
     */
    public static String byte2Base64StringFun(final byte[] b) {
        return Base64.encodeBase64String(b);
    }
}