package com.ec.security.lab;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.net.URL;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;


public class App {

    private static final Logger logger = LogManager.getLogger(App.class);

    public static final String LOCAL_KEYSTORE = "localstore.jks";
    public static final String LOCAL_TESTFILE = "test.out";
    public static final String KEYSTORE_PASS = "password456";
    public static final String SECRET_PASS = "password123";
    public static void main(String[] args) {

        App app = new App();
    }

    public App() {
        this.getKeyStoreContents();
    }

    private void fileIOTest() {
        try
        {
            URL fileRes = this.getClass().getResource("/" + LOCAL_TESTFILE);
            logger.info("File Resource " + fileRes.getFile() + " is null " + (fileRes == null));

            OutputStream resourceOutputStream = new FileOutputStream(fileRes.getFile());
            logger.info("OutputStream resource is null:" + (resourceOutputStream == null));

            resourceOutputStream.close();
            logger.info("Done file IO test" );
        } catch (IOException ioe) {
            logger.info("Error opening file: " + ioe);
            ioe.printStackTrace();
        }
    }

    private void getKeyStoreContents() {
        try {

            InputStream resourceInputStream = this.getClass().getResourceAsStream("/" + LOCAL_KEYSTORE);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(resourceInputStream, KEYSTORE_PASS.toCharArray());
            logger.info("Got keystore instance");

            if (ks.containsAlias("jce-web-key")) {
                Key webKey = ks.getKey("jce-web-key", "".toCharArray());
                logger.info("Got key: " + webKey.getEncoded() + " length:" + webKey.getEncoded().length);
                ByteArrayInputStream bytes = new ByteArrayInputStream(webKey.getEncoded());
                String decodedKey = "";
                int tempByte = bytes.read();
                char tempChar = (char)tempByte;
                while (tempByte > -1) {
                    decodedKey = decodedKey.concat(String.valueOf(tempChar));
                    tempByte = bytes.read();
                    tempChar = (char)tempByte;
                }
                logger.info("Got decodedKey key: " + decodedKey);
            }

            resourceInputStream.close();
        } catch (IOException | NoSuchAlgorithmException | KeyStoreException
                 | CertificateException | UnrecoverableKeyException ikse) {
            logger.info("KeyStore error " + ikse);
            ikse.printStackTrace();
        }
    }
    private void manageKeyStore() {
        try {

            InputStream resourceInputStream = this.getClass().getResourceAsStream("/" + LOCAL_KEYSTORE);
            logger.info("InputStream resource is null:" + (resourceInputStream == null));

            PBEKeySpec keySpec = new PBEKeySpec(SECRET_PASS.toCharArray());
            SecretKey secretKey = SecretKeyFactory.getInstance("PBE").generateSecret(keySpec);

            logger.info("Loading keystore file: " + LOCAL_KEYSTORE);

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            logger.info("Got keystore instance");

            ks.load(resourceInputStream, KEYSTORE_PASS.toCharArray());
            logger.info("Contains webapi alias: " + ks.containsAlias("webapi"));

            ks.setEntry("jce-web-key", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("".toCharArray()));
            logger.info("Set ks entry");

            logger.info("KS contains new alias: " + ks.containsAlias("jce-web-key"));

            URL fileRes = this.getClass().getResource("/" + LOCAL_KEYSTORE);
            logger.info("File Resource " + fileRes.getFile() + " is null " + (fileRes == null));

            OutputStream resourceOutputStream = new FileOutputStream(fileRes.getFile());
            logger.info("OutputStream resource is null:" + (resourceOutputStream == null));

            ks.store(resourceOutputStream, KEYSTORE_PASS.toCharArray());
            resourceInputStream.close();
            resourceOutputStream.close();
            logger.info("Stored new key" );

        } catch (IOException | NoSuchAlgorithmException | KeyStoreException
                 | CertificateException | InvalidKeySpecException ikse) {
            logger.info("KeyStore error " + ikse);
            ikse.printStackTrace();
        }
    }
}
