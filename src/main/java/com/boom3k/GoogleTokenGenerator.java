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
import net.lingala.zip4j.core.ZipFile;
import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.ZipParameters;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;


public class GoogleTokenGenerator {
    private static final String classPath = new File("").getAbsolutePath();
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JacksonFactory JSON_FACTORY = new JacksonFactory();
    private static BufferedReader configurationInputReader = new BufferedReader(new InputStreamReader(System.in));
    private static boolean usesAdminSDK = false;
    private static ArrayList<String> adminSDKScopes = new ArrayList<>();

    static {
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
        adminSDKScopes.add("https://www.googleapis.com/auth/apps.licensing");
        adminSDKScopes.add("https://www.googleapis.com/auth/ediscovery");
    }

    private static String configFileName;
    private static final String getConfigFileNameAppender = "_google_credentials.json";
    private static String userEmail;
    private static String username;

    private static String domain;
    private static String credentialsFilePath;
    private static File serviceAccountKey;
    private static String credentialsZipPassword;
    private static String projectId;
    private static ImmutableSet<String> SCOPES_SET;
    private static ArrayList<String> userScopes = new ArrayList<>();


    public static void main(String[] args) throws IOException, ZipException {

        System.out.println("Beginning the GoogleTokenGenerator process.." +
                "\nPlease have your scopes text file and credentials ready.\nA google.json file will be placed in {" + classPath + "} once the program authorizes the client" +
                "\nPress Enter to begin...");
        configurationInputReader.readLine();
        System.out.println("Enter your account email:");
        userEmail = new BufferedReader(new InputStreamReader(System.in)).readLine();
        domain = userEmail.substring(userEmail.lastIndexOf("@") + 1);
        username = userEmail.substring(0, userEmail.lastIndexOf("@"));
        System.out.println("Will this application require use of the Google Admin SDK? (Y/N)");
        if (configurationInputReader.readLine().toLowerCase().startsWith("y")) {
            usesAdminSDK = true;
        }
        createConfigurationFile();
    }

    static public void createConfigurationFile() throws IOException, ZipException {
        /**--------------Credentials Zip File--------------*/
        //GetZip
        System.out.println("Please use the Java window to specify the location of the zipped Google credentials");

        credentialsFilePath = getFileFromJFC(classPath,
                "ZipFilePath",
                "Select",
                "Zip File",
                "zip")
                .getPath();


        //GetZipPassword
        //credentialsZipPassword = console.readPassword("Enter credentials zip file password: ").toString();
        System.out.println("Enter credentials zip file password:");
        credentialsZipPassword = new BufferedReader(new InputStreamReader(System.in)).readLine().replace("\n", "");


        //Get files file from zip
        System.out.println("ZipFile: " + credentialsFilePath + " > Attempting to unlock..");
        Map<String, InputStream> zipFiles = Zip3k.getAllZippedFiles(credentialsFilePath, credentialsZipPassword);
        System.out.println("ZipFile: " + credentialsFilePath + " > Successfully unlocked!");

        //Get ClientSecrets file from zip
        GoogleClientSecrets googleClientSecrets = new GoogleClientSecrets();
        for (String fileName : zipFiles.keySet()) {
            if (fileName.contains("google_credentials")) {
                continue;
            }
            if (fileName.contains("scopes.txt")) {
                //Set user scopes
                Scanner scopesScanner = new Scanner(zipFiles.get(fileName));
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
                SCOPES_SET = ImmutableSet.copyOf(allScopes);
                SCOPES_SET.forEach(s -> System.out.println(s));
            }

            if (fileName.contains(".json")) {
                InputStream is = zipFiles.get(fileName);
                try {
                    googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new InputStreamReader(is));
                } catch (Exception e) {
                    System.out.println(fileName + " is not a clientSecrets file.");
                }
            }
        }

        //Set GoogleClientSecrets from clientsecrets json file
        System.out.println("Reading ClientSecrets file...");
        System.out.println("Project ClientId: " + googleClientSecrets.getInstalled().getClientId());
        System.out.println("Project  AuthURI: " + googleClientSecrets.getInstalled().getAuthUri());
        System.out.println("Project TokenURI: " + googleClientSecrets.getInstalled().getTokenUri());
        projectId = (String) googleClientSecrets.getInstalled().get("project_id");
        configFileName = username + "_" + projectId + getConfigFileNameAppender;
        System.out.println("Project Id: " + projectId);

        /**--------------Authentication with Google AuthFlow--------------*/
        System.out.println("Google Authentication Flow started....");
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
                .Builder(HTTP_TRANSPORT, JSON_FACTORY, googleClientSecrets, SCOPES_SET.asList())
                .setAccessType("offline")
                .build();
        Credential credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(userEmail);
        System.out.println("Google Authentication Flow ended....");

        /**--------------Store tokens and settings in json file--------------*/
        System.out.println("Writing configuration data to  a new google.json file");
        Map<String, String> configurationJsonTemplate = new HashMap<>();
        configurationJsonTemplate.put("DATE_CREATED", new Date().toString());
        configurationJsonTemplate.put("DOMAIN", domain);
        configurationJsonTemplate.put("USER_EMAIL", userEmail);
        configurationJsonTemplate.put("ACCESS_TOKEN", credential.getAccessToken());
        configurationJsonTemplate.put("REFRESH_TOKEN", credential.getRefreshToken());
        configurationJsonTemplate.put("ADMIN_SCOPES", adminSDKScopes.toString());
        configurationJsonTemplate.put("USER_SCOPES", userScopes.toString());
        configurationJsonTemplate.put("CREDENTIALS_FILE_PATH", credentialsFilePath);
        configurationJsonTemplate.put("CREDENTIALS_PASSWORD", Base64.getEncoder().encodeToString(credentialsZipPassword.getBytes()));
        FileWriter writer = new FileWriter(new java.io.File(configFileName).getAbsolutePath());
            writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(configurationJsonTemplate));
            writer.close();
        System.out.println("Place config file inside of zip folder? (y/n)");

        if (configurationInputReader.readLine().toLowerCase().startsWith("y")) {
            Zip3k.insertFileToZip(
                    credentialsFilePath,
                    new File(configFileName),
                    credentialsZipPassword);
            Files.delete(Paths.get(configFileName));
            System.out.println("Configuration file [" + configFileName + "] created in " + credentialsFilePath + " successfully...");
        } else {
            System.out.println("Configuration file [" + configFileName + "] created in " + classPath + " successfully...");
        }
        System.out.println("************  Google Token Generator End ************");
    }

    public static File getFileFromJFC(String startPath, String title, String buttonTitle, String fileDescription, String fileExtensions) {

        JFileChooser jfc = new JFileChooser(startPath);
        FileNameExtensionFilter filter = new FileNameExtensionFilter(fileDescription, fileExtensions.toLowerCase());
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

    static void inputStreamToFile(InputStream is, String name) throws IOException {
        OutputStream os = new FileOutputStream(name);
        byte[] buffer = new byte[1024];
        int bytesRead;
        //read from is to buffer
        while ((bytesRead = is.read(buffer)) != -1) {
            os.write(buffer, 0, bytesRead);
        }
        is.close();
        //flush OutputStream to write any buffered data to file
        os.flush();
        os.close();
    }


}