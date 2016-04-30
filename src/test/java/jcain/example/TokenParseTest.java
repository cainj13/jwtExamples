package jcain.example;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyPair;

import static org.junit.Assert.assertEquals;

public class TokenParseTest {
    private static final Logger log = LoggerFactory.getLogger(TokenParseTest.class);

    @Test
    public void parseSigAndValidateSubject() {
        final KeyPair keyPair = RsaProvider.generateKeyPair();
        final String token = Jwts.builder().setSubject("user1").signWith(SignatureAlgorithm.RS512, keyPair.getPrivate()).compact();
        log.info("Generated JWT token: ", token);

        final Jws<Claims> parsedJwt = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token);
        log.info("Successfully decrypted JWT ussing public key: " + parsedJwt.toString());
        assertEquals("user1", parsedJwt.getBody().getSubject());
    }
}
