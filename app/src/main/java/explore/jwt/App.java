/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package explore.jwt;
import com.auth0.jwt.interfaces.DecodedJWT;

import explore.jwt.CreateToken;

public class App {

    public static void main(String[] args) {
        String jwt = CreateToken.sign();
        System.out.println(jwt);

        //try to verify
        DecodedJWT verifyJwt = CreateToken.verify(jwt);
        System.out.println(verifyJwt);

    }
}
