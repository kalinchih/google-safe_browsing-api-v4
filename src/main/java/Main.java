import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.safebrowsing.Safebrowsing;
import com.google.api.services.safebrowsing.model.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Main {


    public static final JacksonFactory GOOGLE_JSON_FACTORY = JacksonFactory.getDefaultInstance();
    public static final String GOOGLE_API_KEY = ""; // Google API key
    public static final String GOOGLE_CLIENT_ID = "xx"; // client id
    public static final String GOOGLE_CLIENT_VERSION = "0.0.1"; // client version
    public static final String GOOGLE_APPLICATION_NAME = "xx"; // appication name
    public static final List<String> GOOGLE_THREAT_TYPES = Arrays.asList(new String[]{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"});
    public static final List<String> GOOGLE_PLATFORM_TYPES = Arrays.asList(new String[]{"ANY_PLATFORM"});
    public static final List<String> GOOGLE_THREAT_ENTRYTYPES = Arrays.asList(new String[]{"URL"});
    public static NetHttpTransport httpTransport;

    public static void main(String[] args) throws GeneralSecurityException, IOException {

        httpTransport = GoogleNetHttpTransport.newTrustedTransport();

        List<String> urls = Arrays.asList(new String[]{"http://www.google.com", "https://malware.testing.google.test/testing/malware/"});

        FindThreatMatchesRequest findThreatMatchesRequest = createFindThreatMatchesRequest(urls);

        Safebrowsing.Builder safebrowsingBuilder = new Safebrowsing.Builder(httpTransport, GOOGLE_JSON_FACTORY, null).setApplicationName(GOOGLE_APPLICATION_NAME);
        Safebrowsing safebrowsing = safebrowsingBuilder.build();
        FindThreatMatchesResponse findThreatMatchesResponse = safebrowsing.threatMatches().find(findThreatMatchesRequest).setKey(GOOGLE_API_KEY).execute();

        List<ThreatMatch> threatMatches = findThreatMatchesResponse.getMatches();

        if (threatMatches != null && threatMatches.size() > 0) {
            for (ThreatMatch threatMatch : threatMatches) {
                System.out.println(threatMatch.toPrettyString());
            }
        }
    }


    private static FindThreatMatchesRequest createFindThreatMatchesRequest(List<String> urls) {
        FindThreatMatchesRequest findThreatMatchesRequest = new FindThreatMatchesRequest();

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientId(GOOGLE_CLIENT_ID);
        clientInfo.setClientVersion(GOOGLE_CLIENT_VERSION);
        findThreatMatchesRequest.setClient(clientInfo);

        ThreatInfo threatInfo = new ThreatInfo();
        threatInfo.setThreatTypes(GOOGLE_THREAT_TYPES);
        threatInfo.setPlatformTypes(GOOGLE_PLATFORM_TYPES);
        threatInfo.setThreatEntryTypes(GOOGLE_THREAT_ENTRYTYPES);

        List<ThreatEntry> threatEntries = new ArrayList<ThreatEntry>();

        for (String url : urls) {
            ThreatEntry threatEntry = new ThreatEntry();
            threatEntry.set("url", url);
            threatEntries.add(threatEntry);
        }
        threatInfo.setThreatEntries(threatEntries);
        findThreatMatchesRequest.setThreatInfo(threatInfo);

        return findThreatMatchesRequest;
    }
}
