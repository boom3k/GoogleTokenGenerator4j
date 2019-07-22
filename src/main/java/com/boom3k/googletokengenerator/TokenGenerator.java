package com.boom3k.googletokengenerator;

import boom3k.Zip3k;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.common.collect.ImmutableSet;
import com.google.gson.GsonBuilder;
import net.lingala.zip4j.exception.ZipException;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;


public class TokenGenerator {
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JacksonFactory JSON_FACTORY = new JacksonFactory();

    static public void createConfigurationFile(String configurationName) throws IOException, ZipException {
        System.out.println("************* Google Token Generator Begin *************");

        /**--------------Do Scopes stuff--------------*/
        //Set admin scopes
        final String[] adminSDKScopes = new String[]{
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/admin.reports.usage.readonly",
                "https://www.googleapis.com/auth/admin.directory.user",
                "https://www.googleapis.com/auth/admin.directory.group",
                "https://www.googleapis.com/auth/admin.directory.group.member",
                "https://www.googleapis.com/auth/admin.directory.customer",
                "https://www.googleapis.com/auth/admin.directory.domain",
                "https://www.googleapis.com/auth/apps.groups.settings"
        };

        //Set serviceaccount scopes
        ArrayList<String> allScopes = new ArrayList<>();

        Scanner scopesScanner = new Scanner(new File("scopes.txt"));
        while (scopesScanner.hasNextLine()) {
            String currentLine = scopesScanner.nextLine();
            if (!currentLine.isEmpty()) {
                allScopes.add(scopesScanner.nextLine().replace(",", ""));
            }
        }

        allScopes.addAll(Arrays.asList(adminSDKScopes));
        System.out.println("Project Scopes: ");

        allScopes.forEach(scope -> System.out.println(scope));
        final ImmutableSet<String> SCOPES_SET = ImmutableSet.copyOf(allScopes);

        System.out.println("Enter your admin account email:");
        String adminEmail = new BufferedReader(new InputStreamReader(System.in)).readLine();
        String domain = adminEmail.substring(adminEmail.lastIndexOf("@") + 1);

        /**--------------Credentials Zip File--------------*/
        //GetZip
        System.out.println("Select zipped Google Oauth2 Credentials in separate window");
        String zipPath = getFileFromJFC(new File("").getAbsolutePath(),
                "ZipFilePath",
                "Select")
                .getAbsolutePath();

        //GetZipPassword
        System.out.println("Enter Oauth2 credentials zip file password:");
        String credentialsPassword =
                //console.readPassword("Enter Oauth2 credentials zip file password: ").toString();
                new BufferedReader(new InputStreamReader(System.in)).readLine().replace("\n", "");


        //Get files file from zip
        System.out.println("ZipFile: ," + zipPath + " > Attempting to unlock..");
        Map<String, InputStream> zipFiles = Zip3k.getAllInputStreamsInSize(zipPath, credentialsPassword);
        System.out.println("ZipFile: ," + zipPath + " > Successfully unlocked!");

        //Set GoogleClientSecrets from clientsecret json file
        System.out.println("Reading ClientSecrets file...");
        GoogleClientSecrets googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY,
                new InputStreamReader(zipFiles.get("clientsecret.json")));
        System.out.println("Project ClientId: ," + googleClientSecrets.getInstalled().getClientId());
        System.out.println("Project  AuthURI: ," + googleClientSecrets.getInstalled().getAuthUri());
        System.out.println("Project TokenURI: ," + googleClientSecrets.getInstalled().getTokenUri());


        /**--------------Authentication with Google AuthFlow--------------*/
        System.out.println("Google Authentication Flow started....");
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
                .Builder(HTTP_TRANSPORT, JSON_FACTORY, googleClientSecrets, SCOPES_SET)
                .setAccessType("offline")
                .build();
        Credential credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(adminEmail);
        System.out.println("Google Authentication Flow ended....");
        /**--------------Store tokens and settings in json file--------------*/
        System.out.println("Writing configuration data to ," + configurationName + "_configuration.json");
        Map<String, String> configurationJsonTemplate = new HashMap<>();
        configurationJsonTemplate.put("ACCESS_TOKEN", credential.getAccessToken());
        configurationJsonTemplate.put("REFRESH_TOKEN", credential.getRefreshToken());
        configurationJsonTemplate.put("DOMAIN", domain);
        configurationJsonTemplate.put("ADMIN_EMAIL", adminEmail);
        //configurationJsonTemplate.put("SERVICE_ACCOUNT_EMAIL", "");//TODO: Client_Email from serviceAccountKey or not???
        configurationJsonTemplate.put("CREDENTIALS_FILE_PATH", zipPath);
        configurationJsonTemplate.put("CREDENTIALS_PASSWORD", encodeString(credentialsPassword));
        FileWriter writer = new FileWriter(new java.io.File(configurationName + "_configuration.json").getAbsolutePath());
        writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(configurationJsonTemplate));
        writer.close();
        System.out.println("Configuration file ," + configurationName + "_configuration.json created successfully...");
        System.out.println("************  Google Token Generator End ************");
    }

    private static String encodeString(String trueString) {
        return Base64.getEncoder().encodeToString(trueString.getBytes());
    }

    private static File getFileFromJFC(String startPath, String title, String buttonTitle) {

        JFileChooser jfc = new JFileChooser(startPath);
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Zip File", "zip");
        jfc.setFileFilter(filter);
        jfc.setDialogTitle(title);

        int returnValue = jfc.showDialog(null, buttonTitle);
        if (returnValue != JFileChooser.CANCEL_OPTION) {
            return jfc.getSelectedFile();
        } else {
            System.out.println("No file selected, please rerun application and select a file.");
            System.exit(0);
            return null;
        }
    }

}
