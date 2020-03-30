package com.github.boom3k;

import boom3k.Zip3k;
import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;


public class GoogleTokenGenerator {
    static final String CLASS_PATH = new File("").getAbsolutePath();
    static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    static final JacksonFactory JSON_FACTORY = new JacksonFactory();
    static BufferedReader configurationInputReader = new BufferedReader(new InputStreamReader(System.in));
    static ArrayList<String> adminScopes = new ArrayList<>();
    static ArrayList<String> allScopes = new ArrayList<>();
    static String zipPassword;
    static List<File> files = new ArrayList<>();
    static final String CONFIG_FILENAME_APPENDER = "_google_config.json";
    static String userEmail;
    static String username;
    static String domain;
    static GoogleClientSecrets googleClientSecrets = new GoogleClientSecrets();
    static ImmutableSet<String> SCOPES_SET;
    static ArrayList<String> userScopes = new ArrayList<>();
    static Credential credential;
    static String applicationName;
    static File clientSecretsFile;
    static File serviceAccountKeyFile;
    static File scopesFile;
    static boolean adminSDK;
    static boolean hasBrowser = true;
    static String exportFileName;

    /**
     * @param args 0 - Application Name
     */
    public static void main(String[] args) throws IOException, ZipException {

        //-appname prod
        //-clientSecretsFile C:\OneDrive\devstuff\credentials\prod.da\prod-Gam\client_secret.json
        //-serviceAccountFile C:\OneDrive\devstuff\credentials\prod.da\prod-Gam\scopes.txt
        //-scopesFile:\OneDrive\devstuff\credentials\prod.da\prod-Gam\serviceAccountKey.json
        System.out.println(args.length);
        for (String arg : args) {
            System.out.println(arg);
            String key = arg.split("->")[0];
            String value = arg.split("->")[1];
            switch (key) {
                case "BROWSER":
                    hasBrowser = Boolean.parseBoolean(value);
                    break;
                case "ADMINSDK":
                    adminSDK = Boolean.parseBoolean(value);
                    break;
                case "USEREMAIL":
                    userEmail = value;
                    break;
                case "APPNAME":
                    applicationName = value;
                    break;
                case "CSFILE":
                    clientSecretsFile = new File(value);
                    break;
                case "SAFILE":
                    serviceAccountKeyFile = new File(value);
                    break;
                case "SCOPESFILE":
                    scopesFile = new File(value);
                    break;
                case "PASSWORD":
                    zipPassword = value;
                    break;
            }
        }

        System.out.println("Beginning the GoogleTokenGenerator process.." +
                "\nPlease have you scopes text file and credentials ready.\nA new zip file will be placed in {" + CLASS_PATH + "} " +
                "with Google token and credentials once the program authorizes with the client.");

        /**-------------- Set zipPassword --------------*/
        if (zipPassword == null) {
            setPassword();
        }

        /**-------------- Set applicationName --------------*/
        if (applicationName == null) {
            System.out.print("Enter the application name: ");
            applicationName = configurationInputReader.readLine();
        }

        /**-------------- Set userEmail --------------*/
        if (userEmail == null) {
            System.out.print("Enter your account email: ");
            userEmail = configurationInputReader.readLine();
        }

        /**-------------- Get serviceAccountKey --------------*/
        if (serviceAccountKeyFile != null) {
            getServiceAccountCredential();
        } else {
            System.out.print("Will this application require a serviceAccount? (y/n): ");
            if (configurationInputReader.readLine().toLowerCase().contains("y")) {
                getServiceAccountCredential();
            }
        }


        /**-------------- Get ClientSecrets --------------*/
        if (clientSecretsFile != null) {
            getClientSecrets();
        } else {
            System.out.print("Will this application require a OAuth2 Token? (y/n): ");
            if (configurationInputReader.readLine().toLowerCase().contains("y")) {
                getClientSecrets();
            }
        }

        /**-------------- Retrieve Tokens --------------*/
        domain = userEmail.substring(userEmail.lastIndexOf("@") + 1);
        username = userEmail.substring(0, userEmail.lastIndexOf("@"));
        exportFileName = username + "_" + applicationName + "_credentials";
        getOAuth2Tokens();

    }

    static void setPassword() {
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
    }

    static void getServiceAccountCredential() {
        if (serviceAccountKeyFile == null) {
            System.out.println("Please use the Java window to select the Service AccountKey file");
            serviceAccountKeyFile = getFileFromJFC(CLASS_PATH,
                    "Service AccountKey file",
                    "Select",
                    "Service AccountKey file",
                    "json");
        }
        files.add(serviceAccountKeyFile);
    }

    static void getClientSecrets() throws IOException {
        /**--------------Get Scopes from file--------------*/
        if (scopesFile == null) {
            System.out.println("Please use the Java window to select the text file with the required scopes");
            scopesFile = getFileFromJFC(CLASS_PATH,
                    "Please select the scopes text file",
                    "Select",
                    "Scopes text file",
                    "txt");
        }
        files.add(scopesFile);
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
        allScopes.addAll(userScopes);
        if (adminSDK == false) {
            System.out.print("Will this application require use of the Google Admin SDK? (y/n): ");
            if (configurationInputReader.readLine().toLowerCase().contains("y")) {
                adminSDK = true;
            }
        }

        if (adminSDK == true) {
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
            adminScopes.add("https://www.googleapis.com/auth/admin.directory.device.mobile");
            allScopes.addAll(adminScopes);
        }

        System.out.println("Project Scopes: ");
        SCOPES_SET = ImmutableSet.copyOf(allScopes);
        SCOPES_SET.forEach(scope -> System.out.println(scope));

        /**--------------Get ClientSecrets from file--------------*/
        if (clientSecretsFile == null) {
            System.out.println("Please use the Java window to select the Google Client Secrets file");
            clientSecretsFile = getFileFromJFC(scopesFile.getAbsolutePath(),
                    "Please select the Google Client Secret File",
                    "Select",
                    "Google ClientSecret File",
                    "json");
        }
        files.add(clientSecretsFile);
        googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new FileReader(clientSecretsFile));
        System.out.println("Reading ClientSecrets file...");
        System.out.println("Project ClientId: " + googleClientSecrets.getInstalled().getClientId());
        System.out.println("Project Id: " + googleClientSecrets.getInstalled().get("project_id"));
    }

    static void getOAuth2Tokens() throws IOException, ZipException {
        /**--------------Authentication with Google AuthFlow and return token--------------*/
        startFlow();

        /** -------------------Update Json File ------------------------------*/
        JsonObject clientSecretsJsonData = new Gson().fromJson(new FileReader(clientSecretsFile), JsonObject.class);
        JsonObject tokenData = new JsonObject();
        tokenData.addProperty("created",
                Instant.ofEpochMilli(credential.getClock()
                        .currentTimeMillis())
                        .atZone(ZoneId.systemDefault())
                        .toLocalDate().toString());
        tokenData.addProperty("authorizedUser", userEmail);
        tokenData.addProperty("access_token", credential.getAccessToken());
        tokenData.addProperty("refresh_token", credential.getRefreshToken());
        tokenData.addProperty("admin_scopes", String.valueOf(adminScopes).replaceAll("\"", ""));
        tokenData.addProperty("user_scopes", String.valueOf(userScopes).replaceAll("\"", ""));
        clientSecretsJsonData.add("tokens", tokenData);
        FileWriter writer = new FileWriter(clientSecretsFile);
        writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(clientSecretsJsonData));
        writer.close();
        Files.deleteIfExists(Paths.get(exportFileName + ".zip"));
        Zip3k.zipFile(exportFileName, files, zipPassword);
        System.out.println(exportFileName + ".zip");
        System.out.println("************  Google Token Generator End ************");
    }

    static void startFlow() throws IOException {
        System.out.println("Google Authentication Flow started....");
        GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow
                .Builder(HTTP_TRANSPORT, JSON_FACTORY, googleClientSecrets, SCOPES_SET.asList())
                .setAccessType("offline")
                .build();
        if (hasBrowser == true){
            credential = new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize(userEmail);
        }else{
            String authorizeUrl = flow.newAuthorizationUrl().setRedirectUri("http://localhost").build();
            System.out.println("Paste this url in your browser:\n\n" + authorizeUrl + "\n\n");
            System.out.println("Type the Code you recieved here:");
            GoogleAuthorizationCodeTokenRequest tokenRequest = flow.newTokenRequest(configurationInputReader.readLine());
            tokenRequest.setRedirectUri("urn:ietf:wg:oauth:2.0:oob");
            GoogleTokenResponse tokenResponse = tokenRequest.execute();
            credential = flow.createAndStoreCredential(tokenResponse, userEmail);
        }
        System.out.println("Google Authentication Flow ended....");
    }

    static File getFileFromJFC(String startPath, String title, String buttonTitle, String fileDescription, String fileExtensions) {
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