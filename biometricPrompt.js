// usage (terminal): frida -U -f <package_name(e.g.: com.example.biometric_test)> -l <biometricPrompt.js> 
// Device must be rooted
// Frida server must be running on device


console.log("##### Frida script has started for biometricPrompt")

setImmediate(function() {
    Java.perform(function() {

        // DYNAMIC ACTIVITY DETECTION
        // Detect any activity that gets created to make the script work with any android app regardless
        //  of activity names
        
        var mainActivityDetected = false;
        var biometricHooksSetup = false;

        // Hook the Activity class to detect when activities are created
        try {
            var Activity = Java.use("android.app.Activity");
            console.log("[+] Activity class found");

            Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
                var activityName = this.getClass().getName();
                console.log("[*] Activity created: " + activityName);

                // Check if this looks like a main activity
                var isMainActivity =    activityName.toLowerCase().includes("main") ||
                                        activityName.toLowerCase().includes("launcher") ||
                                        activityName.toLowerCase().includes("splash") ||
                                        activityName.toLowerCase().includes("home");

                if (isMainActivity && !mainActivityDetected) {
                    console.log("[+] Main Activity detected: " + activityName);
                    mainActivityDetected = true;

                    // Set up biometric hooks now that app is ready
                    if (!biometricHooksSetup) {
                        setupBiometricHooks();
                        biometricHooksSetup = true;
                    }
                }

                // call the original onCreate method
                this.onCreate(bundle);
            };
            console.log("[+] Activity detection hooks set up");

        }   catch (err)  {
            console.log("[-] Could not hook Activity class: " + err);
        }


        // APPLICATION-LEVEL HOOKS - fallback
        // If activity detection doesn't work, hook Application class as fallback

        try {
            var Application = Java.use("android.app.Application");
            console.log("[+] Application class found");

            Application.onCreate.implementation = function() {
                console.log("[*] Application started");
                console.log("[*] Setting up biometric hooks at application level");

                // Set up biometric hooks immediately when the app starts
                if (!biometricHooksSetup) {
                    setupBiometricHooks();
                    biometricHooksSetup = true;
                }

                this.onCreate();
            };
            console.log("[+] Application hooks are set up");

        }   catch (err) {
            console.log("[-] Could not hook application class: " + err);
        }

        // BIOMETRIC HOOK SETUP FUNCTION
        // This function contains all biometric interception
        // It's called when mainActivity is detected or when the app starts

        function setupBiometricHooks() {
            console.log("[+] Setting up biometric hooks");

            // Hook BiometricPrompt API
            try {
                var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
                console.log("[+] BiometricPrompt class found");

                // Hook method 1: authenticate(PromptInfo)  - without CryptoObject - lack of Keystore
                BiometricPrompt.authenticate.overload("androidx.biometric.BiometricPrompt$PromptInfo").implementation = function (promptInfo) {
                    console.log("[+] BiometricPrompt.authenticate(PromptInfo) called *");
                    console.log("[*] No CryptoObject was used in this call *");

                    // most process the same with method 2
                    var biometricCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");

                    // Hook success callback
                    biometricCallback.onAuthenticationSucceeded.implementation = function (authenticationResult) {
                        console.log("[+] HOOKED: onAuthenticationSucceeded was called *");

                        var cryptoObject = authenticationResult.getCryptoObject();
                        if (cryptoObject) {
                            console.log("[*] CryptoObject retrieved from AuthenticationResult *");

                        }   else {
                            console.log("[*] No CryptoObject in AuthenticationResult *");
                        }

                        this.onAuthenticationSucceeded(authenticationResult);
                    };

                    // Hook failure callback
                    biometricCallback.onAuthenticationFailed.implementation = function() {
                        console.log("[-] HOOKED: onAuthenticationFailed called *");
                        this.onAuthenticationFailed();
                    };

                    // Hook error callback
                    biometricCallback.onAuthenticationError.implementation = function(errorCode, errString) {
                        console.log("[-]  HOOKED: onAuthenticationError called. Error: " + errString + " *");
                        this.onAuthenticationError(errorCode, errString);
                    };

                    console.log("[*] BiometricPrompt callback hooks are in place *\n");
                    this.authenticate(promptInfo);
                };

                // Hook method 2: authenticate(PromptInfo, CryptoObject) - biometric with encryption
                BiometricPrompt.authenticate.overload("androidx.biometric.BiometricPrompt$PromptInfo", 
                    "androidx.biometric.BiometricPrompt$CryptoObject").implementation = function(promptInfo, cryptoObject) {
                    
                    console.log("[+]  BiometricPrompt.authenticate(PromptInfo, CryptoObject) called");

                    if (cryptoObject) {
                        console.log("[+] CryptoObject found **");
                        console.log("[*] CryptoObject class: " + cryptoObject.getClass().getName() + " **");

                        if (cryptoObject.getCipher()) console.log("[+] Contains a Cipher object for encryption/decryption **");
                        if (cryptoObject.getMac()) console.log("[+] Contains a Mac object for message authentication **");
                        if (cryptoObject.getSignature()) console.log("[+] Contains a Signature object for digital signatures **");
                    
                    } else {
                        console.log("[-] CryptoObject parameters present but null **");
                    }

                    // same with method 1
                    var biometricCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");

                    // Hook success callback
                    biometricCallback.onAuthenticationSucceeded.implementation = function (authenticationResult) {
                        console.log("[+] HOOKED: onAuthenticationSucceeded was called **");

                        var cryptoObject = authenticationResult.getCryptoObject();
                        if (cryptoObject) {
                            console.log("[*] CryptoObject retrieved from AuthenticationResult **");

                        }   else {
                            console.log("[*] No CryptoObject in AuthenticationResult **");
                        }

                        this.onAuthenticationSucceeded(authenticationResult);
                    };

                    // Hook failure callback
                    biometricCallback.onAuthenticationFailed.implementation = function() {
                        console.log("[-] HOOKED: onAuthenticationFailed called **");
                        this.onAuthenticationFailed();
                    };

                    // Hook error callback
                    biometricCallback.onAuthenticationError.implementation = function(errorCode, errString) {
                        console.log("[-]  HOOKED: onAuthenticationError called. Error: " + errString + " **");
                        this.onAuthenticationError(errorCode, errString);
                    };

                    console.log("[*] BiometricPrompt callback hooks are in place. **\n");
                    this.authenticate(promptInfo, cryptoObject);
                };
                console.log("[+] BiometricPrompt hooks are in place #\n");

            }   catch (err) {
                console.log("[-] Could not hook BiometricPrompt: " + err + " #");
            }

            // Hook method 3: fingerprintManager API (Deprecated API)
            try {
                var fingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
                console.log("[+] FingerprintManager class found");
                
                fingerprintManager.authenticate.overload("android.hardware.fingerprint.FingerprintManager$CryptoObject",
                    "android.os.CancellationSignal", "int", "android.hardware.fingerprint.FingerprintManager$AuthenticationCallback",
                    "android.os.Handler").implementation = function(crypto, cancel, flags, callback, handler) {

                        console.log("[+] DEPRECATED FingerprintManager class found ***");

                        if (crypto) {
                            console.log("[+] CryptoObject was passed to FingerprintManager ***");
                            console.log("[+] CryptoObject class: " + crypto.getClass().getName() + " ***");
                        } else {
                            console.log("[-] No CryptoObject used with FingerprintManager ***");
                        }

                        // Hook callback methods
                        var callbackClass = Java.use("android.hardware.fingerprint.FingerprintManager$AuthenticationCallback");

                        callbackClass.onAuthenticationSucceeded.implementation = function (authResult) {
                            console.log("[+] FingerprintManager onAuthenticatedSucceeded called ***");
                            this.onAuthenticationSucceeded(authResult);
                        };

                        // Hook failure callback
                        callbackClass.onAuthenticationFailed.implementation = function() {
                        console.log("[-] FingerprintManager onAuthenticationFailed called ***");
                        this.onAuthenticationFailed();
                        };
                        // Hook error callback
                        callbackClass.onAuthenticationError.implementation = function(errorCode, errString) {
                        console.log("[-] FingerprintManager onAuthenticationError called. Error: " + errString + " ***");
                        this.onAuthenticationError(errorCode, errString);
                        };

                        return this.authenticate(crypto, cancel, flags, callback, handler);
                    };
                    console.log("[+] FingerprintManager hooks are set up ***\n");

            }   catch (err) {
                    console.log("[-] Could not hook FingerprintManager: " + err + " ***");
            }

            // Hook any method that might trigger biometric authentication
            // Made to work with any app
            try {
                // Hook common biometric-related method names
                var commonBiometricMethods = [
                    "authenticate",
                    "authenticateWithCrypto",
                    "authenticateWithFingerprintManager",
                    "showBiometricPrompt",
                    "startBiometricAuth",
                    "loginWithBiometric"
                ];

                // Try to hook methods in common classes
                var commonClasses = [
                    "android.app.Activity",
                    "androidx.appcompat.app.AppCompatActivity",
                    "androidx.fragment.app.FragmentActivity"
                ];

                commonClasses.forEach(function(className) {
                    try {
                        var Class = Java.use(className);
                        commonBiometricMethods.forEach(function(methodName) {
                            try {
                                // Try to hook the method if it exists
                                Class[methodName].implementation = function() {
                                    console.log("[*] " + className + "." + methodName + "() called $");
                                    console.log("[*] Possible biometric authentication method $");
                                    return this[methodName].apply(this, arguments);
                                };
                                console.log("[+] HOOKED: " + className + "." + methodName);
                            }   catch (e) {
                                // Continue if method doesn't exist
                            }
                        });
                    }   catch (e) {
                        // Continue if class doesn't exist
                    }
                });

            } catch (err) {
                console.log("[-] Could not hook common biometric methods: " + err);
            }

            console.log("[+] Biometric hooks set up completed\n");
        }
    });
});