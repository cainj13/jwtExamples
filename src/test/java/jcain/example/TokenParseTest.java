package jcain.example;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.Assert.assertEquals;

public class TokenParseTest {
    private static final Logger log = LoggerFactory.getLogger(TokenParseTest.class);

    @Test
    public void parseSigAndValidateSubject() {
        final KeyPair keyPair = RsaProvider.generateKeyPair();
        final String token = Jwts.builder().setSubject("user1").signWith(SignatureAlgorithm.RS512, keyPair.getPrivate()).compact();
        log.info("Generated JWT token: {}", token);

        final Jws<Claims> parsedJwt = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token);
        log.info("Successfully decrypted JWT using public key: {}", parsedJwt.toString());
        assertEquals("user1", parsedJwt.getBody().getSubject());
    }

    @Test
    public void parseSigAndValidateFromPublicKeyString() throws Exception {
        final KeyPair generateKeyPair = RsaProvider.generateKeyPair();
        final String token = Jwts.builder().setSubject("user1").signWith(SignatureAlgorithm.RS512, generateKeyPair.getPrivate()).compact();
        log.info("Generated JWT token: {}", token);

        final String publicKeyString = Base64.encode(generateKeyPair.getPublic().getEncoded());

        log.info("Parsing generated public key: {}", publicKeyString);
        byte[] byteKey = Base64.decode(publicKeyString);
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        final PublicKey publicKey =  kf.generatePublic(X509publicKey);

        final Jws<Claims> parsedJwt = Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
        log.info("Successfully decrypted JWT using parsed public key: {}", parsedJwt.toString());
        assertEquals("user1", parsedJwt.getBody().getSubject());

    }
}
