package explore.jwt;

import com.auth0.jwt.*;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.*;
import com.auth0.jwt.exceptions.*;
import com.auth0.jwt.interfaces.*;
import java.util.Date;


public class CreateToken {
    public static void main(String[] args) {
        System.out.println("yo");
    }

    public static String sign(){

        try {
            Algorithm algorithm = Algorithm.HMAC256("secret");
            String token = JWT.create()
                .withIssuer("auth0")
                .sign(algorithm);
            return token;
        } catch (JWTCreationException exception){
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        return "";
    } 

    public static DecodedJWT verify(){
        String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
        
        Algorithm algorithm = Algorithm.HMAC256("secret");
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("auth0")
            .build(); //Reusable verifier instance
        DecodedJWT jwt = verifier.verify(token);
        return jwt;
        
    }

}
