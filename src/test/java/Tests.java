public class Tests {
    /*@Test
    public void test() throws IOException, ZipException {
        com.boom3k.TokenGenerator.createConfigurationFile(
                "TestApp",
                "rhenderson.da@usaid.gov",
                "da_credentials.zip",
                "rhenderson",
                false
        );
    }*/

    /*@Test
    public void x() throws FileNotFoundException {
        JsonObject configurationJson = (JsonObject) new JsonParser().parse(new FileReader("TestApp_google.json"));
        //Get the zip file path
        String zipFilePath = configurationJson.get("CREDENTIALS_FILE_PATH").getAsString();

        //Get the zip file's password
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] bytes = decoder.decode(configurationJson.get("CREDENTIALS_PASSWORD").getAsString());
        String zipPassword = new String(bytes, UTF_8);

        String[] x = configurationJson.get("USER_SCOPES")
                .toString()
                .replace("[", "")
                .replace("]", "")
                .replace("\"","")
                .split(",");
        System.out.println(x);

    }*/
}
