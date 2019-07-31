import com.boom3k.googletokengenerator.TokenGenerator;
import net.lingala.zip4j.exception.ZipException;

import java.io.IOException;

public class Tests {
    public static void test() throws IOException, ZipException {
        TokenGenerator.createConfigurationFile(
                "TestApp","rhenderson.da@usaid.gov","da_credentials.zip","rhenderson"
        );
    }
}
