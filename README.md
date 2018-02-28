Sample Codes for Google Safe Browsing v4 Java SDK
===


Check and set these variables on the src/main/java/Main class.
- public static final String GOOGLE_API_KEY = ""; // Google API key
- public static final String GOOGLE_CLIENT_ID = "xx"; // client id
- public static final String GOOGLE_CLIENT_VERSION = "0.0.1"; // client version
- public static final String GOOGLE_APPLICATION_NAME = "xx"; // appication name

After executing this method, you will get the result.

```
{
  "cacheDuration" : "300s",
  "platformType" : "ANY_PLATFORM",
  "threat" : {
    "url" : "https://malware.testing.google.test/testing/malware/"
  },
  "threatEntryType" : "URL",
  "threatType" : "MALWARE"
}
{
  "cacheDuration" : "300s",
  "platformType" : "ANY_PLATFORM",
  "threat" : {
    "url" : "https://malware.testing.google.test/testing/malware/"
  },
  "threatEntryType" : "URL",
  "threatType" : "SOCIAL_ENGINEERING"
}

```

Google API Reference: https://developers.google.com/safe-browsing/v4/ 