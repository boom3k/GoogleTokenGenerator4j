package com.boom3k;

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
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import net.lingala.zip4j.exception.ZipException;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.util.*;


public class GoogleTokenGenerator {
    private static final String classPath = new File("").getAbsolutePath();

    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JacksonFactory JSON_FACTORY = new JacksonFactory();
    private static BufferedReader configurationInputReader = new BufferedReader(new InputStreamReader(System.in));
    private static boolean usesAdminSDK = false;
    private static JsonObject configurationJson;
    private static String configFileName = "google.json";
    private static String adminEmail;
    private static String credentialsFilePath;
    private static String credentialsZipPassword;


    public static void main(String[] args) throws IOException, ZipException {
        System.out.println("Beginning the configuration.json creation process.." +
                "\nPlease place the 'scopes.txt' and your encrypted clientsecrets and/or serviceaccountkey zip folder in this location {" + classPath + "}" +
                "\nPress Enter once both files are set..");
        configurationInputReader.readLine();
        System.out.println("Will this client require usage Google's AdminSDK? (Y/N)");
        if (configurationInputReader.readLine().toLowerCase().startsWith("y")) {
            usesAdminSDK = true;
        }
        System.out.println("AdminSDK used = " + usesAdminSDK);
        createConfigurationFile(usesAdminSDK);
        configurationJson = (JsonObject) new JsonParser().parse(new FileReader(configFileName));
    }

    static public void createConfigurationFile(boolean usesAdminSDK) throws IOException, ZipException {
        System.out.println("************* Google Token Generator Begin *************");
        /**--------------Do Scopes stuff--------------*/
        //Set admin scopes
        ArrayList<String> adminSDKScopes = new ArrayList<>();
        {
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.reports.audit.readonly");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.reports.usage.readonly");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.user");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.group.member");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.group");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.customer");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.resource.calendar");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.directory.domain");
            adminSDKScopes.add("https://www.googleapis.com/auth/apps.groups.settings");
            adminSDKScopes.add("https://www.googleapis.com/auth/androidmanagement");
            adminSDKScopes.add("https://www.googleapis.com/auth/apps.groups.migration");
            adminSDKScopes.add("https://www.googleapis.com/auth/apps.groups.settings");
            adminSDKScopes.add("https://www.googleapis.com/auth/admin.datatransfer");
            adminSDKScopes.add("https://www.googleapis.com/auth/cloud-platform");
            adminSDKScopes.add("https://www.googleapis.com/auth/cloud_search");
            adminSDKScopes.add("https://www.googleapis.com/auth/ediscovery");
        }


        //Set user scopes
        ArrayList<String> userScopes = new ArrayList<>();
        Scanner scopesScanner = new Scanner(new File("scopes.txt"));
        while (scopesScanner.hasNextLine()) {
            String currentLine = scopesScanner.nextLine();
            if (!currentLine.isEmpty() && currentLine.startsWith("https://")) {
                if (currentLine.contains(",")) {
                    userScopes.add(currentLine.replace(",", ""));
                    continue;
                }
                userScopes.add(currentLine);
            }
        }
        scopesScanner.close();

        ArrayList<String> allScopes = new ArrayList<>();
        if (usesAdminSDK == true) {
            allScopes.addAll(adminSDKScopes);
        }
        allScopes.addAll(userScopes);

        System.out.println("Project Scopes: ");
        final ImmutableSet<String> SCOPES_SET = ImmutableSet.copyOf(allScopes);
        SCOPES_SET.forEach(s -> System.out.println(s));

        System.out.println("Enter your admin account email:");

        adminEmail = new BufferedReader(new InputStreamReader(System.in)).readLine();

        String domain = adminEmail.substring(adminEmail.lastIndexOf("@") + 1);

        /**--------------Credentials Zip File--------------*/
        //GetZip
        System.out.println("Select zipped Google Oauth2 Credentials in separate window");
        credentialsFilePath = getFileFromJFC(new File("").getAbsolutePath(),
                "ZipFilePath",
                "Select")
                .getPath();


        //GetZipPassword
        System.out.println("Enter credentials zip file password:");
        credentialsZipPassword =
                //console.readPassword("Enter Oauth2 credentials zip file password: ").toString();
                new BufferedReader(new InputStreamReader(System.in)).readLine().replace("\n", "");


        //Get files file from zip
        System.out.println("ZipFile: " + credentialsFilePath + " > Attempting to unlock..");
        Map<String, InputStream> zipFiles = Zip3k.getAllZippedFiles(credentialsFilePath, credentialsZipPassword);
        System.out.println("ZipFile: " + credentialsFilePath + " > Successfully unlocked!");

        //Get ClientSecrets file from zip
        GoogleClientSecrets googleClientSecrets = new GoogleClientSecrets();
        for (String fileName : zipFiles.keySet()) {
            InputStream data = zipFiles.get(fileName);
            try {
                System.out.println("Reading file " + fileName);
                googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(data));
                System.out.println(fileName + ": is a Clientsecret file");
                break;
            } catch (Exception e) {
                System.out.println(fileName + " is not a Clientsecret file");
            }
        }


        //Set GoogleClientSecrets from clientsecret json file
        System.out.println("Reading ClientSecrets file...");
        System.out.println("Project ClientId: " + googleClientSecrets.getInstalled().getClientId());
        System.out.println("Project  AuthURI: " + googleClientSecrets.getInstalled().getAuthUri());
        System.out.println("Project TokenURI: " + googleClientSecrets.getInstalled().getTokenUri());


        /**--------------Authentication with Google AuthFlow--------------*/
        System.out.println("Google Authentication Flow started....");
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
                .Builder(HTTP_TRANSPORT, JSON_FACTORY, googleClientSecrets, SCOPES_SET.asList())
                .setAccessType("offline")
                .build();
        Credential credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(adminEmail);
        System.out.println("Google Authentication Flow ended....");


        /**--------------Store tokens and settings in json file--------------*/
        System.out.println("Writing configuration data to  a new google.json file");
        Map<String, String> configurationJsonTemplate = new HashMap<>();
        configurationJsonTemplate.put("DATE_CREATED", new Date().toString());
        configurationJsonTemplate.put("ACCESS_TOKEN", credential.getAccessToken());
        configurationJsonTemplate.put("REFRESH_TOKEN", credential.getRefreshToken());
        configurationJsonTemplate.put("DOMAIN", domain);
        configurationJsonTemplate.put("ADMIN_EMAIL", adminEmail);
        configurationJsonTemplate.put("CREDENTIALS_FILE_PATH", credentialsFilePath);
        configurationJsonTemplate.put("CREDENTIALS_PASSWORD", Base64.getEncoder().encodeToString(credentialsZipPassword.getBytes()));
        configurationJsonTemplate.put("ADMIN_SCOPES", adminSDKScopes.toString());
        configurationJsonTemplate.put("USER_SCOPES", userScopes.toString());
        FileWriter writer = new FileWriter(new java.io.File("google.json").getAbsolutePath());
        writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(configurationJsonTemplate));
        writer.close();
        System.out.println("Configuration file google.json created successfully...");
        System.out.println("************  Google Token Generator End ************");
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