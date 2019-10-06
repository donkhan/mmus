package controllers;

import org.paseto4j.version1.Paseto;
import play.Logger;
import play.mvc.Controller;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

public class Application extends Controller {

    public static void index() {
        render();
    }

    private static String decode(byte[] secretKey,String encryptedToken) throws SignatureException{
        Logger.debug("Encrypted Token " + encryptedToken);
        Logger.debug("SecretKey Length " + secretKey.length);
        String token = Paseto.parse(secretKey, encryptedToken, "");
        Logger.debug("Decrypted Token is: " + token);
        return token;
    }

    private static String getKey(String filename) throws IOException {
        String strKeyPEM = "";
        BufferedReader br = new BufferedReader(new FileReader(filename));
        String line;
        while ((line = br.readLine()) != null) {
            strKeyPEM += line + "\n";
        }
        br.close();
        return strKeyPEM;
    }

    public static byte[] getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
        String publicKeyPEM = key;
        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyPEM = publicKeyPEM.trim();
        Logger.debug("Key PEM " +publicKeyPEM + " Length " + publicKeyPEM.length());
        byte[] keyByte = Base64.getMimeDecoder().decode(publicKeyPEM);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(keyByte));
        return pubKey.getEncoded();
    }

    private static String testUMobile(String encryptedToken) throws SignatureException{
        String serverFileName = "conf/key.pem";
        try {
            byte[] secretKey = getPublicKeyFromString(getKey(serverFileName));
            String decryptedToken = decode(secretKey,encryptedToken);
            return decryptedToken;
        }catch(Throwable t){
            Logger.error("Error " + t.toString());
        }
        return "Failure";
    }

    /**
     * @param payload - string
     * @throws SignatureException
     */


    public static void parse(String payload) throws SignatureException{
        Logger.debug("Parse... payload " + payload);
        //payload = "v1.public.TGV0IHVzIGdvIHRvIFN1bmdhaSBHYWJhabbidKkNCNRPdCqhaNgJXE5q95Gc7mZYm1vAHicEtVRlLWpM1X_eiMPt5Ebij1Ckv9DLYCquNYN80JuBcV072gDaNwR9qPpfg3fzgnfCLBDyqOcfpbMMMzbEuFL7oMt0ckyVfiL-YFFAhWozLfl4KuKJtGnL3Xv0K_7eMqrKf3ukgDYFA2xwTxdB5ZP1FjGmtasZe6PLc6tilIZilC9FWUOPQLeoB3KvJCzw_dJEeojOqd-bXC4MKTupOLVxBwG3BQx0oQhteoQVPNuzlOHsctlKa2pWllm2GeebkC99M8lYPDK3XZYLpJR-0hUVJXEqtpPeUAy8GVx1pZR2arFd1m4";
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength = 0;

        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        } catch(Throwable t){
            Logger.error(t.getMessage());
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed

        try {
            String decryptedData = testUMobile(payload);
            renderText(decryptedData);
        }catch(Throwable t){
            Logger.error(t.getMessage());
        }
    }

}