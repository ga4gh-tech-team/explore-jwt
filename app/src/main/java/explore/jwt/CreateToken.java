package explore.jwt;

import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.*;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.*;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.*;



public class CreateToken {

    public static String sign(String secret){

        try {
            Map<String, Object> headerClaims = new HashMap();
            headerClaims.put("typ", "JWT");
            headerClaims.put("alg", "RS256");
            headerClaims.put("jku", "<JKS-URL>");
            headerClaims.put("kid", "<key-identifier>");
            
            Map<String, Object> passportMap = new HashMap();
            passportMap.put("type", "<passport-visa-type>");
            passportMap.put("asserted", "<seconds-since-epoch>");
            passportMap.put("value", "<value-string>");
            passportMap.put("source", "<source-URL>");

            Algorithm algorithm = Algorithm.HMAC256("secret");
            String token = JWT.create()
                .withIssuer("auth0")
                .withHeader(headerClaims)
                .withClaim("iss","<issuer-URL>")
                .withClaim("sub","<subject-identifier>")
                .withClaim("iss","")
                .withClaim("jti","<token-identifier>")
                .withClaim("iat","<seconds-since-epoch>")
                .withClaim("exp","<seconds-since-epoch>")
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
            Algorithm algorithm = Algorithm.HMAC256("secret");
            JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer("auth0")
                .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            return jwt;
        } catch (JWTDecodeException exception){
            throw exception;
        }
        
    }

    public static DecodedJWT decode(){
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
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
