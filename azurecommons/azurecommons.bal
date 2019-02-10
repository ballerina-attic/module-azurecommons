import ballerina/crypto;
import ballerina/encoding;
import ballerina/http;
import ballerina/time;

public const STORAGE_API_VERSION = "2018-03-28";

# Generates the storage services common headers.
#
# + return - The header values as a map
public function generateStorageCommonHeaders() returns map<string> {
    string dateString = generateStorageDateString();
    map<string> headers = { "x-ms-date": dateString, "x-ms-version": STORAGE_API_VERSION };
    return headers;
}

# Generates canonicalized header string from the given header map.
#
# + headers - The header map
# + return - The canonicalized header string
public function generateCanonicalizedHeadersString(map<string> headers) returns string {
    // TODO: sort headers - when sort functionality is availble
    string result = "";
    foreach var (key, value) in headers {
        if (key.indexOf("x-ms-") == 0) {
            result = result + key.toLower().trim() + ":" + value.trim() + "\n";
        }
    }
    return result;
}

# Generates the storage services date string.
#
# + return - The storage services date string
public function generateStorageDateString() returns string {
    string DATE_TIME_FORMAT = "EEE, dd MMM yyyy HH:mm:ss z";
    time:Time time = time:currentTime();
    time:Time standardTime = time:toTimeZone(time, "GMT");
    return time:format(standardTime, DATE_TIME_FORMAT);
}

# Generates a storage error with the given HTTP response.
#
# + resp - The HTTP response with the error
# + return - The generates `error` object
public function generateStorageError(http:Response resp) returns error {
    xml errorXml = check resp.getXmlPayload();
    string message = errorXml.Message.getTextValue();
    string authError = errorXml.AuthenticationErrorDetail.getTextValue();
    if (authError != "") {
        message = message + " AuthError: " + authError;
    }
    error err = error(errorXml.Code.getTextValue(), { message: message });
    return untaint err;
}

# Populates the headers with the generated shared key lite signature.
#
# + account - The storage account name
# + accessKey - The access key
# + canonicalizedResource - The canonicalized resource
# + verb - The HTTP verb
# + headers - The current headers
# + return - Retuns an `error` if there is any issue populating the header value
public function populateSharedKeyLiteStorageAuthorizationHeader(string account, string accessKey, 
                                string canonicalizedResource, string verb, map<string> headers) returns error? {
    string signature = check generateSharedKeyLiteStorageServiceSignature(accessKey, canonicalizedResource, 
                                                                          verb, headers);
    headers["Authorization"] = "SharedKeyLite " + account + ":" + signature;
}

# Populates request headers.
#
# + req - The HTTP request
# + headers - The header map to populate the HTTP request
public function populateRequestHeaders(http:Request req, map<string> headers) {
    foreach var (k, v) in headers {
        req.setHeader(k, v);
    }
}

# Generates the shared key lite signature.
#
# + accessKey - The access key
# + canonicalizedResource - The canonicalized resource
# + verb - The HTTP verb
# + headers - The current headers
# + return - The signature value, or else an `error` if there is any issue
public function generateSharedKeyLiteStorageServiceSignature(string accessKey, string canonicalizedResource, 
                                                     string verb, map<string> headers) returns string|error {
    string canonicalizedHeaders = generateCanonicalizedHeadersString(headers);
    string? value = headers["Content-Type"];
    string contentType = "";
    if (value is string) {
        contentType = value;
    }
    string contentMD5 = "";
    value = headers["Content-MD5"];
    if (value is string) {
        contentMD5 = value;
    }
    string date = "";
    value = headers["Date"];
    if (value is string) {
        date = value;
    }
    string stringToSign = verb.toUpper() + "\n" +
                          contentMD5 + "\n" + 
                          contentType + "\n" +
                          date + "\n" + 
                          canonicalizedHeaders +   
                          canonicalizedResource;
    
    byte[] key = check encoding:decodeBase64(accessKey);
    return encoding:encodeBase64(crypto:hmacSha256(stringToSign.toByteArray("UTF-8"), key));
}
