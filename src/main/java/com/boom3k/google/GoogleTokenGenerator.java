package com.boom3k.google;

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
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import net.lingala.zip4j.exception.ZipException;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class GoogleTokenGenerator {
    private static final String CLASS_PATH = new File("").getAbsolutePath();
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JacksonFactory JSON_FACTORY = new JacksonFactory();
    private static BufferedReader configurationInputReader = new BufferedReader(new InputStreamReader(System.in));
    private static ArrayList<String> adminScopes = new ArrayList<>();
    private static String zipPassword;
    private static List<File> files = new ArrayList<>();
    private static String appName;
    private static final String CONFIG_FILENAME_APPENDER = "_google_config.json";
    private static String userEmail;
    private static String username;
    private static String domain;
    private static GoogleClientSecrets googleClientSecrets = new GoogleClientSecrets();
    private static ImmutableSet<String> SCOPES_SET;
    private static ArrayList<String> userScopes = new ArrayList<>();

    /**
     * @param args 0 - Application Name
     */
    public static void main(String[] args) throws IOException, ZipException {
        appName = args[0];
        System.out.println("Beginning the GoogleTokenGenerator process.." +
                "\nPlease have your scopes text file and credentials ready.\nA new zip file will be placed in {" + CLASS_PATH + "} " +
                "with Google token and credentials once the program authorizes with the client." +
                "\nPress Enter to begin...");
        configurationInputReader.readLine();
        System.out.print("Enter your account email: ");
        userEmail = configurationInputReader.readLine();
        domain = userEmail.substring(userEmail.lastIndexOf("@") + 1);
        username = userEmail.substring(0, userEmail.lastIndexOf("@"));

        /**--------------Set zipPassword--------------*/
        int passwordAttempt = 0;
        String validatedZipPassword;
        do {
            if (passwordAttempt > 0) {
                System.out.println("Passwords do not match...\n" +
                        "Clearing the previous input. Please try again...");
            }
            zipPassword = new String(System.console().readPassword("Enter the a new password for the config file:"));
            validatedZipPassword = new String(System.console().readPassword("Please enter the password again:"));
            passwordAttempt++;
        } while (!zipPassword.contentEquals(validatedZipPassword));

        /**-------------- Get ServiceAccountKey File --------------*/
        System.out.print("Will this application require a serviceAccount? (y/n): ");
        if (configurationInputReader.readLine().toLowerCase().contains("y")) {
            System.out.println("Please use the Java window to select the Service AccountKey file");
            File serviceAccountKeyFile = getFileFromJFC(CLASS_PATH,
                    "Service AccountKey file",
                    "Select",
                    "Service AccountKey file",
                    "json");
            files.add(serviceAccountKeyFile);
        }

        /**-------------- Get ClientSecrets File --------------*/
        System.out.println("Will this application require a OAuth2 Token? (y/n): ");
        if (configurationInputReader.readLine().toLowerCase().contains("y")) {
            /**--------------Get Scopes from file--------------*/
            System.out.println("Please use the Java window to select the text file with the required scopes");
            File scopesFile = getFileFromJFC(CLASS_PATH,
                    "Please select the scopes text file",
                    "Select",
                    "Scopes text file",
                    "txt");

            Scanner scopesScanner = new Scanner(new FileReader(scopesFile));
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
            allScopes.addAll(userScopes);
            System.out.print("Will this application require use of the Google Admin SDK? (y/n): ");
            if (configurationInputReader.readLine().toLowerCase().contains("y")) {
                adminScopes.add("https://www.googleapis.com/auth/admin.reports.audit.readonly");
                adminScopes.add("https://www.googleapis.com/auth/admin.reports.usage.readonly");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.user");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.group.member");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.group");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.customer");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.resource.calendar");
                adminScopes.add("https://www.googleapis.com/auth/admin.directory.domain");
                adminScopes.add("https://www.googleapis.com/auth/apps.groups.settings");
                adminScopes.add("https://www.googleapis.com/auth/androidmanagement");
                adminScopes.add("https://www.googleapis.com/auth/apps.groups.migration");
                adminScopes.add("https://www.googleapis.com/auth/apps.groups.settings");
                adminScopes.add("https://www.googleapis.com/auth/admin.datatransfer");
                adminScopes.add("https://www.googleapis.com/auth/cloud-platform");
                adminScopes.add("https://www.googleapis.com/auth/cloud_search");
                adminScopes.add("https://www.googleapis.com/auth/apps.licensing");
                adminScopes.add("https://www.googleapis.com/auth/ediscovery");
                allScopes.addAll(adminScopes);
            }

            System.out.println("Project Scopes: ");
            SCOPES_SET = ImmutableSet.copyOf(allScopes);
            SCOPES_SET.forEach(scope -> System.out.println(scope));
            System.out.println("Please use the Java window to select the Google Client Secrets file");
            File clientSecretsFile = getFileFromJFC(scopesFile.getAbsolutePath(),
                    "Please select the Google Client Secret File",
                    "Select",
                    "Google ClientSecret File",
                    "json");
            files.add(clientSecretsFile);
            googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new FileReader(clientSecretsFile));
            System.out.println("Reading ClientSecrets file...");
            System.out.println("Project ClientId: " + googleClientSecrets.getInstalled().getClientId());
            System.out.println("Project Id: " + googleClientSecrets.getInstalled().get("project_id"));

            /**--------------Authentication with Google AuthFlow and return token--------------*/
            System.out.print("Authentication flow will open a new browser window/tab. Press enter when ready...");
            configurationInputReader.readLine();
            System.out.println("Google Authentication Flow started....");
            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
                    .Builder(HTTP_TRANSPORT, JSON_FACTORY, googleClientSecrets, SCOPES_SET.asList())
                    .setAccessType("offline")
                    .build();
            Credential credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(userEmail);
            System.out.println("Google Authentication Flow ended....");

            /** -------------------Update Json File ------------------------------*/
            JsonObject clientSecretsJsonData = new Gson().fromJson(new FileReader(clientSecretsFile), JsonObject.class);
            JsonObject tokenData = new JsonObject();
            tokenData.addProperty("created",
                    Instant.ofEpochMilli(credential.getClock()
                            .currentTimeMillis())
                            .atZone(ZoneId.systemDefault())
                            .toLocalDate().toString());
            tokenData.addProperty("access_token", credential.getAccessToken());
            tokenData.addProperty("refresh_token", credential.getRefreshToken());
            clientSecretsJsonData.add("tokens", tokenData);
            FileWriter writer = new FileWriter(clientSecretsFile);
            writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(clientSecretsJsonData));
            writer.close();
            Zip3k.zipFile(username + "_" + appName + "_credentials", files, zipPassword);
            System.out.println("************  Google Token Generator End ************");
        }
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

}