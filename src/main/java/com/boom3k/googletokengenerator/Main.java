package com.boom3k.googletokengenerator;

import net.lingala.zip4j.exception.ZipException;

import java.io.IOException;

public class Main {

    public static void main(String[] args) throws IOException, ZipException {
        TokenGenerator.createConfigurationFile("google_configuration.json");
    }
}
