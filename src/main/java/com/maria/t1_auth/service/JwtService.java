package com.maria.t1_auth.service;

import com.maria.t1_auth.config.JwtConfig;
import com.maria.t1_auth.model.User;
import com.maria.t1_auth.utils.PemUtils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    private final RSAPrivateKey signPriv;
    private final RSAPublicKey  signPub;
    private final RSAPrivateKey encPriv;
    private final RSAPublicKey  encPub;
    private final long          ACCESS_EXP;
    private final long          REFRESH_EXP;

    public JwtService(JwtConfig prop) {
        this.signPriv  = PemUtils.readPrivateKey(prop.getSign().getPrivateKey(), "RSA");
        this.signPub   = PemUtils.readPublicKey (prop.getSign().getPublicKey(),  "RSA");
        this.encPriv   = PemUtils.readPrivateKey(prop.getEnc().getPrivateKey(),  "RSA");
        this.encPub    = PemUtils.readPublicKey (prop.getEnc().getPublicKey(),   "RSA");
        this.ACCESS_EXP  = prop.getAccessExp();
        this.REFRESH_EXP = prop.getRefreshExp();
    }

    public String generateAccessToken(User user) throws JOSEException {
        return generateToken(user, ACCESS_EXP);
    }
    public String generateRefreshToken(User user) throws JOSEException {
        return generateToken(user, REFRESH_EXP);
    }

    private String generateToken(User user, long expMillis) throws JOSEException {
        var now = new Date();
        var claims = new JWTClaimsSet.Builder()
                .subject(user.getUsername())
                .claim("role", user.getRoles().stream().map(Enum::name).toList())
                .issueTime(now)
                .expirationTime(new Date(now.getTime()+expMillis))
                .jwtID(UUID.randomUUID().toString())
                .build();

        var signed = new SignedJWT(
                new JWSHeader(JWSAlgorithm.RS256), claims);
        signed.sign(new RSASSASigner(signPriv));

        var jweHeader = new JWEHeader.Builder(
                JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .contentType("JWT")
                .build();
        var jwe = new JWEObject(jweHeader, new Payload(signed));
        jwe.encrypt(new RSAEncrypter(encPub));

        return jwe.serialize();
    }

    public JWTClaimsSet parseAccessToken(String token) throws Exception {
        return parseToken(token);
    }
    public JWTClaimsSet parseRefreshToken(String token) throws Exception {
        return parseToken(token);
    }

    private JWTClaimsSet parseToken(String token) throws Exception {
        var jwe = JWEObject.parse(token);
        jwe.decrypt(new RSADecrypter(encPriv));

        var signed = SignedJWT.parse(jwe.getPayload().toString());
        if (!signed.verify(new RSASSAVerifier(signPub)))
            throw new BadJWTException("Invalid signature");

        var claims = signed.getJWTClaimsSet();
        if (claims.getExpirationTime().before(new Date()))
            throw new BadJWTException("Token expired");

        return claims;
    }
}





