package explore.jwt;

import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.*;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.*;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.*;
import java.util.Date;



public class CreateToken {

    public static String sign(String secret, Map<String, Object> passportMap, String subjectID, String tokenID, int expDays){

        try {
            Map<String, Object> headerClaims = new HashMap();
            headerClaims.put("typ", "JWT");
            headerClaims.put("alg", "RS256");
            headerClaims.put("jku", new String[]{"<JKS-URL>"});
            headerClaims.put("kid", "<key-identifier>");            

            Algorithm algorithm = Algorithm.HMAC256(secret);
            String token = JWT.create()
                .withIssuer("https://ga4gh.org/")
                .withHeader(headerClaims)
                .withClaim("sub",subjectID)
                .withArrayClaim("scope", new String[]{"openid"})
                .withClaim("jti",tokenID)
                .withClaim("iat", System.currentTimeMillis()/1000)
                .withClaim("exp",(System.currentTimeMillis()/1000) + expDays * 86400)
                .withClaim("ga4gh_visa_v1", passportMap)
                .sign(algorithm);
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    } 

    public static DecodedJWT verify(String token, String secret){
        try{
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            return jwt;
        } catch (JWTDecodeException exception){
            throw exception;
        }
        
    }

    public static DecodedJWT decode(String token){
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt;
        } catch (JWTDecodeException exception){
            //Invalid token
            DecodedJWT jwt = JWT.decode(token);
            return jwt;
        }
    }

}
