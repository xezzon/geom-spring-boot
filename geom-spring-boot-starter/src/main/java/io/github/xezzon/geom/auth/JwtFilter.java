package io.github.xezzon.geom.auth;

import static com.google.auth.http.AuthHttpConstants.AUTHORIZATION;
import static com.google.auth.http.AuthHttpConstants.BEARER;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.stereotype.Component;

/**
 * @author xezzon
 */
@Slf4j
@Component
@WebFilter(urlPatterns = "/*")
public class JwtFilter implements Filter {

  public static final String PUBLIC_KEY_HEADER = "X-Public-Key";

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
    if (request instanceof HttpServletRequest httpRequest) {
      String authorization = httpRequest.getHeader(AUTHORIZATION);
      String publicKeyPem = httpRequest.getHeader(PUBLIC_KEY_HEADER);
      if (authorization == null || publicKeyPem == null) {
        return;
      }
      if (!authorization.startsWith(BEARER) || publicKeyPem.isEmpty()) {
        return;
      }
      String token = authorization.substring(BEARER.length()).trim();
      try {
        ECPublicKey publicKey = getPublicKey(publicKeyPem);
        JWTVerifier verifier = JWT.require(Algorithm.ECDSA256(publicKey)).build();
        DecodedJWT jwt = verifier.verify(token);
        JwtClaim claim = JwtClaimWrapper.from(jwt).get();
      } catch (Exception e) {
        log.debug("Failed to parse the JWT. token: {}; key: {}", token, publicKeyPem, e);
      }
    }
  }

  private static ECPublicKey getPublicKey(String publicKeyString) throws IOException {
    PemObject pemObject = new PemObject("PUBLIC KEY", Base64.getDecoder().decode(publicKeyString));
    String publicKeyPem;
    try (
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter)
    ) {
      pemWriter.writeObject(pemObject);
      pemWriter.flush();
      publicKeyPem = stringWriter.toString();
    }
    try (PEMParser pemParser = new PEMParser(new StringReader(publicKeyPem))) {
      SubjectPublicKeyInfo publicKeyInfo =
          SubjectPublicKeyInfo.getInstance(pemParser.readObject());
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      return (ECPublicKey) converter.getPublicKey(publicKeyInfo);
    }
  }
}
