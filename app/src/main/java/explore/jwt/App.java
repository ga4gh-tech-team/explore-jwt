/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package explore.jwt;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.interfaces.DecodedJWT;

import explore.jwt.CreateToken;

public class App {

    public static void main(String[] args) {

        Map<String, Object> passportMap = buildVisa("AffiliationAndRole", 5000000, "", "", new String[]{""}, new String[]{"<by-identifier>"});
        String jwt = CreateToken.sign("secret", passportMap, "sid", "tid", 10);
        System.out.println(jwt);

        //try to verify
        DecodedJWT verifyJwt = CreateToken.verify(jwt,"secret");
        System.out.println(verifyJwt);

    }

    public static Map<String, Object> buildVisa(String type, Integer asserted, String value, String source, String[] conditions, String[] by){
        Map<String, Object> passportMap = new HashMap();
            passportMap.put("type", type);
            passportMap.put("asserted", asserted);
            passportMap.put("value", value); 
            passportMap.put("source", source);
            passportMap.put("conditions", conditions);
            passportMap.put("by", by);

        return passportMap;
    }
}
