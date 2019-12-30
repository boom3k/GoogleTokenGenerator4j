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
import net.lingala.zip4j.exception.ZipException;

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
    private static String zipPassword;
    private static List<File> files = new ArrayList<>();
    private static String zipFileName;

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
    private static final String getConfigFileNameAppender = "_google_config.json";
    private static String userEmail;
    private static String username;
    private static String domain;
    private static String credentialsFilePath;
    private static File serviceAccountKey;
    private static String credentialsZipPassword;
    private static String projectId;
    private static GoogleClientSecrets googleClientSecrets = new GoogleClientSecrets();
    private static ImmutableSet<String> SCOPES_SET;
    private static ArrayList<String> userScopes = new ArrayList<>();
    private static boolean argsGiven;
    private static String clientSecret;
    private static String clientID;

    public static void main(String[] args) throws IOException, ZipException {
        if (args.length > 0) {
            argsGiven = true;
            clientID = args[0];
            projectId = args[1];
            List<String> redirectUris = new ArrayList<>();
            redirectUris.add("urn:ietf:wg:oauth:2.0:oob");
            redirectUris.add("http:..localhost");
            googleClientSecrets = new GoogleClientSecrets().setInstalled(new GoogleClientSecrets.Details()
                    .setClientId(clientID)
                    .setAuthUri("https://accounts.google.com/o/oauth2/auth")
                    .setTokenUri("https://oauth2.googleapis.com/token")
                    .setRedirectUris(redirectUris));
        } else System.out.println("No initial params found....");
        System.out.println("Beginning the GoogleTokenGenerator process.." +
                "\nPlease have your scopes text file and credentials ready.\nA **_google_config.zip file will be placed in {" + classPath + "} once the program authorizes the client" +
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
        System.out.println("Please use the Java window to select the text file with the required scopes");
        File scopesFile = getFileFromJFC(classPath,
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
        if (usesAdminSDK == true) {
            allScopes.addAll(adminSDKScopes);
        }
        allScopes.addAll(userScopes);
        System.out.println("Project Scopes: ");
        SCOPES_SET = ImmutableSet.copyOf(allScopes);
        SCOPES_SET.forEach(s -> System.out.println(s));

        System.out.println("Will this application require a serviceAccountKey? (y/n)");
        if (configurationInputReader.readLine().toLowerCase().contains("y")) {
            System.out.println("Please use the Java window to select the Service AccountKey file");
            File serviceAccountKeyFile = getFileFromJFC(scopesFile.getPath(),
                    "Service AccountKey file",
                    "Select",
                    "Service AccountKey file",
                    "json");
            files.add(serviceAccountKeyFile);
        }


        if (argsGiven == true) {
            System.out.println("Application ClientId: " + clientID +
                    "\n\tPlease enter the associated client secret:");
            clientSecret = configurationInputReader.readLine();
            googleClientSecrets.getDetails().setClientSecret(clientSecret);
        } else {
            System.out.println("Please use the Java window to select the Google Client Secrets file");
            File clientSecretsFile = getFileFromJFC(scopesFile.getPath(),
                    "Please select the Google Client Secret File",
                    "Select",
                    "Google ClientSecret File",
                    "json");
            files.add(clientSecretsFile);
            googleClientSecrets = GoogleClientSecrets.load(JSON_FACTORY, new FileReader(clientSecretsFile));
        }


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
        System.out.println("Enter file password: ");
        zipPassword = configurationInputReader.readLine();
        do {
            System.out.println("Please enter the file password again for validation: ");
        } while (!zipPassword.equals(configurationInputReader.readLine()));


        File configFile = new File(configFileName);
        FileWriter writer = new FileWriter(configFile);
        writer.write(new GsonBuilder().setPrettyPrinting().create().toJson(configurationJsonTemplate));
        writer.close();
        files.add(configFile);
        zipFileName = username + "_" + projectId;
        Zip3k.zipFile(zipFileName, files, zipPassword);
        Files.delete(Paths.get(configFile.getAbsolutePath()));
        System.out.println("Configuration file [" + configFileName + "] created in " + credentialsFilePath + " successfully...");
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