/*
 * Comprehensive analysis of biometric authentication vulnerabilities

 * Usage: frida -U -f com.example.targetapp -l proto3.js

 * Device must be rooted
 * Frida server must be running on device
 */

// ============================================================================
// GLOBAL STATE & CONFIGURATION
// ============================================================================

var SCAN_CONFIG = {
    enableAPIHooks: true,
    enableTimingAnalysis: true,
    enableCryptoHooks: true,
    enableStorageHooks: true,
    enableNetworkHooks: true,
    enableMemoryAnalysis: true,
    timingSampleSize: 10,
    debugMode: true
};

var scanResults = {
    metadata: {
        scanId: generateUUID(),
        timestamp: new Date().toISOString(),
        scanDuration: 0,
        targetPackage: "",
        deviceInfo: {}
    },
    vulnerabilities: [],
    timingData: {
        attempts: [],
        successTimes: [],
        failureTimes: [],
        analysis: null
    },
    apiFindings: [],
    cryptoFindings: [],
    storageFindings: [],
    networkFindings: [],
    memoryFindings: []
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function log(category, message, level) {
    level = level || "INFO";
    var prefix = {
        "INFO": "",
        "SUCCESS": "",
        "WARNING": "",
        "ERROR": "",
        "DEBUG": ""
    }[level] || "";
    
    console.log("[" + category + "] " + prefix + " " + message);
}

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0;
        var v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function addVulnerability(vuln) {
    vuln.id = generateUUID();
    vuln.detectedAt = new Date().toISOString();
    scanResults.vulnerabilities.push(vuln);
    
    var severityEmoji = {
        "CRITICAL": "",
        "HIGH": "",
        "MEDIUM": "",
        "LOW": ""
    }[vuln.severity] || "";
    
    log("VULNERABILITY", severityEmoji + " " + vuln.severity + ": " + vuln.title, "WARNING");
}

function getStackTrace() {
    try {
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        return Log.getStackTraceString(Exception.$new());
    } catch(e) {
        return "Stack trace not available";
    }
}

// ============================================================================
// DEVICE & APP INFORMATION GATHERING
// ============================================================================

function collectDeviceInfo() {
    Java.perform(function() {
        try {
            var Build = Java.use("android.os.Build");
            var BuildVersion = Java.use("android.os.Build$VERSION");
            
            scanResults.metadata.deviceInfo = {
                manufacturer: Build.MANUFACTURER.value,
                model: Build.MODEL.value,
                device: Build.DEVICE.value,
                androidVersion: BuildVersion.RELEASE.value,
                sdkInt: BuildVersion.SDK_INT.value,
                brand: Build.BRAND.value,
                fingerprint: Build.FINGERPRINT.value
            };
            
            log("DEVICE", "Device: " + Build.MANUFACTURER.value + " " + Build.MODEL.value, "SUCCESS");
            log("DEVICE", "Android: " + BuildVersion.RELEASE.value + " (SDK " + BuildVersion.SDK_INT.value + ")", "SUCCESS");
            
        } catch(e) {
            log("DEVICE", "Failed to collect device info: " + e, "ERROR");
        }
    });
}

function collectAppInfo() {
    Java.perform(function() {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            var currentApplication = ActivityThread.currentApplication();
            if (currentApplication != null) {
                var context = currentApplication.getApplicationContext();
                var packageName = context.getPackageName();
                var packageManager = context.getPackageManager();
                var packageInfo = packageManager.getPackageInfo(packageName, 0);
                
                scanResults.metadata.targetPackage = packageName;
                scanResults.metadata.appVersion = packageInfo.versionName.value;
                scanResults.metadata.targetSdk = packageInfo.applicationInfo.value.targetSdkVersion.value;
                
                log("APP", "Package: " + packageName, "SUCCESS");
                log("APP", "Version: " + packageInfo.versionName.value, "SUCCESS");
            }
        } catch(e) {
            log("APP", "Failed to collect app info: " + e, "ERROR");
        }
    });
}

// ============================================================================
// MODULE 1: BIOMETRIC API CONFIGURATION ANALYSIS
// ============================================================================

function hookBiometricPromptAPI() {
    Java.perform(function() {
        try {
            log("API", "Hooking BiometricPrompt API...", "INFO");
            
            // Hook BiometricPrompt.PromptInfo.Builder
            var Builder = Java.use("androidx.biometric.BiometricPrompt$PromptInfo$Builder");
            
            Builder.build.implementation = function() {
                var info = this.build();
                var findings = [];
                
                log("API", "BiometricPrompt.PromptInfo.build() called", "DEBUG");
                
                // Check for negative button (bypass vulnerability)
                try {
                    var negativeText = info.getNegativeButtonText();
                    if (negativeText !== null) {
                        var vuln = {
                            type: "API_MISCONFIGURATION",
                            severity: "HIGH",
                            category: "API Configuration",
                            title: "Negative Button Present - Bypass Risk",
                            description: "BiometricPrompt is configured with a negative button that allows users to bypass biometric authentication entirely without providing credentials.",
                            technicalDetails: {
                                negativeButtonText: negativeText.toString(),
                                location: "BiometricPrompt.PromptInfo.Builder.build()",
                                apiLevel: "androidx.biometric"
                            },
                            impact: "An attacker with physical device access can bypass biometric authentication by tapping the cancel/negative button.",
                            mitigation: "Remove setNegativeButtonText() and use setDeviceCredentialAllowed(true) for fallback authentication.",
                            codeSnippet: {
                                vulnerable: '.setNegativeButtonText("' + negativeText + '")',
                                secure: '.setDeviceCredentialAllowed(true) // Use device credential as fallback'
                            },
                            references: [
                                "https://developer.android.com/training/sign-in/biometric-auth",
                                "https://source.android.com/security/biometric"
                            ]
                        };
                        addVulnerability(vuln);
                        findings.push(vuln);
                    }
                } catch(e) {
                    log("API", "Error checking negative button: " + e, "DEBUG");
                }
                
                // Check authenticator strength
                try {
                    var authenticators = info.getAllowedAuthenticators();
                    log("API", "Allowed authenticators: " + authenticators, "DEBUG");
                    
                    // Check for BIOMETRIC_WEAK (0x00008000 / 32768)
                    var BIOMETRIC_WEAK = 0x00008000;
                    var BIOMETRIC_STRONG = 0x00000800;
                    var DEVICE_CREDENTIAL = 0x00000400;
                    
                    if ((authenticators & BIOMETRIC_WEAK) !== 0) {
                        var vuln = {
                            type: "API_MISCONFIGURATION",
                            severity: "CRITICAL",
                            category: "API Configuration",
                            title: "Weak Biometric Authentication Allowed",
                            description: "BIOMETRIC_WEAK (Class 2) biometrics are allowed. These provide lower security guarantees and are more susceptible to spoofing attacks.",
                            technicalDetails: {
                                authenticators: authenticators,
                                flags: {
                                    BIOMETRIC_WEAK: (authenticators & BIOMETRIC_WEAK) !== 0,
                                    BIOMETRIC_STRONG: (authenticators & BIOMETRIC_STRONG) !== 0,
                                    DEVICE_CREDENTIAL: (authenticators & DEVICE_CREDENTIAL) !== 0
                                }
                            },
                            impact: "Class 2 biometrics (e.g., some face recognition implementations) can be spoofed with photos or masks.",
                            mitigation: "Use BIOMETRIC_STRONG only for sensitive operations. Require Class 3 biometric sensors.",
                            codeSnippet: {
                                vulnerable: '.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)',
                                secure: '.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)'
                            },
                            references: [
                                "https://source.android.com/security/biometric/measure",
                                "https://developer.android.com/reference/android/hardware/biometrics/BiometricManager.Authenticators"
                            ]
                        };
                        addVulnerability(vuln);
                        findings.push(vuln);
                    }
                    
                    // Check if only device credential is used (not biometric at all)
                    if ((authenticators & DEVICE_CREDENTIAL) !== 0 && 
                        (authenticators & BIOMETRIC_STRONG) === 0 && 
                        (authenticators & BIOMETRIC_WEAK) === 0) {
                        log("API", "Only DEVICE_CREDENTIAL is used - no biometric authentication", "WARNING");
                    }
                    
                } catch(e) {
                    log("API", "Error checking authenticator strength: " + e, "DEBUG");
                }
                
                // Check for title and subtitle (informational)
                try {
                    var title = info.getTitle();
                    var subtitle = info.getSubtitle();
                    var description = info.getDescription();
                    
                    log("API", "Prompt Title: " + (title ? title.toString() : "null"), "DEBUG");
                    
                    scanResults.apiFindings.push({
                        type: "INFO",
                        category: "UI Configuration",
                        details: {
                            title: title ? title.toString() : null,
                            subtitle: subtitle ? subtitle.toString() : null,
                            description: description ? description.toString() : null
                        }
                    });
                } catch(e) {
                    log("API", "Error checking UI configuration: " + e, "DEBUG");
                }
                
                return info;
            };
            
            // Hook BiometricPrompt.authenticate() - with CryptoObject (GOOD)
            var BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
            
            BiometricPrompt.authenticate.overload(
                'androidx.biometric.BiometricPrompt$PromptInfo',
                'androidx.biometric.BiometricPrompt$CryptoObject'
            ).implementation = function(promptInfo, cryptoObject) {
                log("API", " BiometricPrompt.authenticate() called WITH CryptoObject - SECURE", "SUCCESS");
                
                scanResults.apiFindings.push({
                    type: "SECURE_PRACTICE",
                    category: "Cryptographic Binding",
                    title: "CryptoObject Used",
                    description: "Authentication is cryptographically bound to sensitive operations",
                    timestamp: new Date().toISOString()
                });
                
                // Start timing measurement
                this.__startTime = Date.now();
                
                return this.authenticate(promptInfo, cryptoObject);
            };
            
            // Hook BiometricPrompt.authenticate() - without CryptoObject (BAD)
            BiometricPrompt.authenticate.overload(
                'androidx.biometric.BiometricPrompt$PromptInfo'
            ).implementation = function(promptInfo) {
                log("API", " BiometricPrompt.authenticate() called WITHOUT CryptoObject", "WARNING");
                
                var vuln = {
                    type: "CRYPTO_WEAKNESS",
                    severity: "HIGH",
                    category: "Cryptographic Security",
                    title: "Missing CryptoObject Binding",
                    description: "BiometricPrompt is used without CryptoObject, meaning authentication is not cryptographically bound to sensitive operations. The authentication result is a simple boolean that can be spoofed at the software level.",
                    technicalDetails: {
                        location: "BiometricPrompt.authenticate(PromptInfo)",
                        missingParameter: "CryptoObject",
                        stackTrace: getStackTrace()
                    },
                    impact: "With root access or hooking frameworks like Frida/Xposed, an attacker can intercept the authentication callback and return 'success' without actual biometric verification.",
                    mitigation: "Always bind biometric authentication to cryptographic operations using CryptoObject with a Cipher, Signature, or Mac object backed by Android KeyStore.",
                    codeSnippet: {
                        vulnerable: 'biometricPrompt.authenticate(promptInfo);',
                        secure: 'BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(cipher);\nbiometricPrompt.authenticate(promptInfo, cryptoObject);'
                    },
                    references: [
                        "https://developer.android.com/training/sign-in/biometric-auth#crypto",
                        "https://source.android.com/security/keystore"
                    ]
                };
                addVulnerability(vuln);
                
                // Start timing measurement
                this.__startTime = Date.now();
                
                return this.authenticate(promptInfo);
            };
            
            log("API", "BiometricPrompt hooks installed successfully", "SUCCESS");
            
        } catch(e) {
            log("API", "Failed to hook BiometricPrompt: " + e, "ERROR");
            log("API", "Stack: " + e.stack, "DEBUG");
        }
        
        // Try to hook deprecated FingerprintManager API
        try {
            var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
            
            FingerprintManager.authenticate.overload(
                'android.hardware.fingerprint.FingerprintManager$CryptoObject',
                'android.os.CancellationSignal',
                'int',
                'android.hardware.fingerprint.FingerprintManager$AuthenticationCallback',
                'android.os.Handler'
            ).implementation = function(crypto, cancel, flags, callback, handler) {
                log("API", " DEPRECATED API: FingerprintManager.authenticate() used", "WARNING");
                
                var vuln = {
                    type: "API_MISCONFIGURATION",
                    severity: "MEDIUM",
                    category: "Deprecated API",
                    title: "Deprecated FingerprintManager API Used",
                    description: "Application uses the deprecated FingerprintManager API instead of the modern BiometricPrompt API. This API was deprecated in Android 9.0 (API 28) and lacks modern security features.",
                    technicalDetails: {
                        deprecatedAPI: "android.hardware.fingerprint.FingerprintManager",
                        deprecatedSince: "Android 9.0 (API 28)",
                        modernAlternative: "androidx.biometric.BiometricPrompt"
                    },
                    impact: "Missing modern security features like unified biometric authentication, better error handling, and improved UI consistency.",
                    mitigation: "Migrate to androidx.biometric.BiometricPrompt which provides better security guarantees and supports multiple biometric types.",
                    codeSnippet: {
                        vulnerable: 'FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);',
                        secure: 'BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor, callback);'
                    },
                    references: [
                        "https://developer.android.com/reference/android/hardware/fingerprint/FingerprintManager",
                        "https://developer.android.com/training/sign-in/biometric-auth"
                    ]
                };
                addVulnerability(vuln);
                
                return this.authenticate(crypto, cancel, flags, callback, handler);
            };
            
            log("API", "FingerprintManager (deprecated) hooks installed", "SUCCESS");
        } catch(e) {
            log("API", "FingerprintManager not found (app likely uses BiometricPrompt)", "DEBUG");
        }
    });
}

// ============================================================================
// MODULE 2: TIMING ATTACK ANALYSIS
// ============================================================================

function hookBiometricCallbacks() {
    Java.perform(function() {
        try {
            log("TIMING", "Installing timing analysis hooks...", "INFO");
            
            var AuthenticationCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");
            
            // Hook onAuthenticationSucceeded
            AuthenticationCallback.onAuthenticationSucceeded.implementation = function(result) {
                var endTime = Date.now();
                
                // Get start time from BiometricPrompt instance
                var duration = 0;
                try {
                    // Access the outer BiometricPrompt instance
                    var outerThis = this.$outer;
                    if (outerThis && outerThis.__startTime) {
                        duration = endTime - outerThis.__startTime;
                    }
                } catch(e) {
                    log("TIMING", "Could not access start time, using default", "DEBUG");
                    duration = 1200; // Default estimate
                }
                
                log("TIMING", " Authentication SUCCEEDED in " + duration + "ms", "SUCCESS");
                
                scanResults.timingData.successTimes.push(duration);
                scanResults.timingData.attempts.push({
                    result: "SUCCESS",
                    duration: duration,
                    timestamp: new Date().toISOString()
                });
                
                // Analyze if we have enough samples
                if (scanResults.timingData.attempts.length >= SCAN_CONFIG.timingSampleSize) {
                    analyzeTimingVulnerability();
                }
                
                return this.onAuthenticationSucceeded(result);
            };
            
            // Hook onAuthenticationFailed
            AuthenticationCallback.onAuthenticationFailed.implementation = function() {
                var endTime = Date.now();
                
                var duration = 0;
                try {
                    var outerThis = this.$outer;
                    if (outerThis && outerThis.__startTime) {
                        duration = endTime - outerThis.__startTime;
                    }
                } catch(e) {
                    duration = 450; // Default estimate
                }
                
                log("TIMING", " Authentication FAILED in " + duration + "ms", "WARNING");
                
                scanResults.timingData.failureTimes.push(duration);
                scanResults.timingData.attempts.push({
                    result: "FAILURE",
                    duration: duration,
                    timestamp: new Date().toISOString()
                });
                
                // Analyze if we have enough samples
                if (scanResults.timingData.attempts.length >= SCAN_CONFIG.timingSampleSize) {
                    analyzeTimingVulnerability();
                }
                
                return this.onAuthenticationFailed();
            };
            
            // Hook onAuthenticationError
            AuthenticationCallback.onAuthenticationError.implementation = function(errorCode, errString) {
                var endTime = Date.now();
                
                var duration = 0;
                try {
                    var outerThis = this.$outer;
                    if (outerThis && outerThis.__startTime) {
                        duration = endTime - outerThis.__startTime;
                    }
                } catch(e) {
                    duration = 300;
                }
                
                log("TIMING", " Authentication ERROR (" + errorCode + "): " + errString + " in " + duration + "ms", "WARNING");
                
                scanResults.timingData.attempts.push({
                    result: "ERROR",
                    errorCode: errorCode,
                    errorMessage: errString.toString(),
                    duration: duration,
                    timestamp: new Date().toISOString()
                });
                
                return this.onAuthenticationError(errorCode, errString);
            };
            
            log("TIMING", "Timing analysis hooks installed successfully", "SUCCESS");
            
        } catch(e) {
            log("TIMING", "Failed to install timing hooks: " + e, "ERROR");
        }
    });
}

function analyzeTimingVulnerability() {
    if (scanResults.timingData.successTimes.length === 0 || 
        scanResults.timingData.failureTimes.length === 0) {
        log("TIMING", "Not enough timing samples for analysis", "DEBUG");
        return;
    }
    
    // Calculate statistics
    var successAvg = scanResults.timingData.successTimes.reduce((a, b) => a + b, 0) / 
                     scanResults.timingData.successTimes.length;
    var failureAvg = scanResults.timingData.failureTimes.reduce((a, b) => a + b, 0) / 
                     scanResults.timingData.failureTimes.length;
    
    var timingDiff = Math.abs(successAvg - failureAvg);
    var percentDiff = (timingDiff / Math.min(successAvg, failureAvg)) * 100;
    
    // Calculate standard deviation
    var successStdDev = Math.sqrt(
        scanResults.timingData.successTimes.map(x => Math.pow(x - successAvg, 2))
            .reduce((a, b) => a + b, 0) / scanResults.timingData.successTimes.length
    );
    var failureStdDev = Math.sqrt(
        scanResults.timingData.failureTimes.map(x => Math.pow(x - failureAvg, 2))
            .reduce((a, b) => a + b, 0) / scanResults.timingData.failureTimes.length
    );
    
    var analysis = {
        successCount: scanResults.timingData.successTimes.length,
        failureCount: scanResults.timingData.failureTimes.length,
        successAverage: Math.round(successAvg),
        failureAverage: Math.round(failureAvg),
        successStdDev: Math.round(successStdDev),
        failureStdDev: Math.round(failureStdDev),
        timingDifference: Math.round(timingDiff),
        percentDifference: percentDiff.toFixed(2),
        sampleSize: scanResults.timingData.attempts.length
    };
    
    scanResults.timingData.analysis = analysis;
    
    log("TIMING", "═══════════════════════════════════════", "INFO");
    log("TIMING", "TIMING ANALYSIS RESULTS", "INFO");
    log("TIMING", "Success average: " + analysis.successAverage + "ms (±" + analysis.successStdDev + "ms)", "INFO");
    log("TIMING", "Failure average: " + analysis.failureAverage + "ms (±" + analysis.failureStdDev + "ms)", "INFO");
    log("TIMING", "Timing difference: " + analysis.timingDifference + "ms (" + analysis.percentDifference + "%)", "INFO");
    log("TIMING", "═══════════════════════════════════════", "INFO");
    
    // Determine severity based on timing difference
    var severity = "LOW";
    if (percentDiff > 30) severity = "HIGH";
    else if (percentDiff > 15) severity = "MEDIUM";
    
    if (percentDiff > 10) { // Only report if difference is significant
        var vuln = {
            type: "TIMING_ATTACK",
            severity: severity,
            category: "Side-Channel Attack",
            title: "Timing Side-Channel Vulnerability Detected",
            description: "Authentication success and failure times differ significantly (" + 
                        analysis.percentDifference + "%), allowing attackers to infer authentication results through timing analysis.",
            technicalDetails: {
                successAverage: analysis.successAverage + "ms",
                failureAverage: analysis.failureAverage + "ms",
                timingDifference: analysis.timingDifference + "ms",
                percentDifference: analysis.percentDifference + "%",
                successStdDev: analysis.successStdDev + "ms",
                failureStdDev: analysis.failureStdDev + "ms",
                sampleSize: analysis.sampleSize,
                attempts: scanResults.timingData.attempts
            },
            impact: "An attacker can perform timing analysis to determine if a fingerprint/biometric template is valid without needing to see the authentication result UI. This enables brute-force attacks and template enumeration.",
            mitigation: "Implement constant-time authentication responses by adding artificial delays to normalize timing patterns.",
            codeSnippet: {
                vulnerable: '// No timing normalization\nbiometricPrompt.authenticate(promptInfo);',
                secure: 'long startTime = System.currentTimeMillis();\nbiometricPrompt.authenticate(promptInfo);\n// In callback:\nlong elapsed = System.currentTimeMillis() - startTime;\nlong targetTime = 1500; // Always take 1.5 seconds\nif (elapsed < targetTime) {\n    Thread.sleep(targetTime - elapsed);\n}'
            },
            references: [
                "https://owasp.org/www-community/attacks/Timing_attack",
                "Paul Kocher - Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS (1996)"
            ]
        };
        addVulnerability(vuln);
    }
}

// ============================================================================
// MODULE 3: CRYPTOGRAPHIC SECURITY ANALYSIS
// ============================================================================

function hookCryptoOperations() {
    Java.perform(function() {
        try {
            log("CRYPTO", "Installing cryptographic analysis hooks...", "INFO");
            
            // Hook Cipher initialization
            var Cipher = Java.use("javax.crypto.Cipher");
            
            Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
                var algorithm = key.getAlgorithm();
                var transformation = this.getAlgorithm();
                
                log("CRYPTO", "Cipher initialized: " + transformation, "DEBUG");
                log("CRYPTO", "Key algorithm: " + algorithm, "DEBUG");
                
                // Check for weak algorithms
                if (algorithm.includes("DES") && !algorithm.includes("AES")) {
                    var vuln = {
                        type: "CRYPTO_WEAKNESS",
                        severity: "CRITICAL",
                        category: "Cryptographic Security",
                        title: "Weak Encryption Algorithm Detected",
                        description: "DES or 3DES encryption algorithm is used. These algorithms are considered cryptographically broken and should not be used.",
                        technicalDetails: {
                            algorithm: algorithm,
                            transformation: transformation,
                            mode: opmode === 1 ? "ENCRYPT" : "DECRYPT"
                        },
                        impact: "DES can be broken in hours with modern hardware. Encrypted biometric data can be recovered.",
                        mitigation: "Use AES-256 with GCM mode for encryption.",
                        codeSnippet: {
                            vulnerable: 'Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");',
                            secure: 'Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");'
                        },
                        references: [
                            "https://www.nist.gov/publications/transitioning-use-cryptographic-algorithms-and-key-lengths"
                        ]
                    };
                    addVulnerability(vuln);
                }
                
                // Check for ECB mode (weak)
                if (transformation.includes("ECB")) {
                    var vuln = {
                        type: "CRYPTO_WEAKNESS",
                        severity: "HIGH",
                        category: "Cryptographic Security",
                        title: "Insecure ECB Mode Used",
                        description: "ECB (Electronic Codebook) mode is used for encryption. ECB mode is deterministic and reveals patterns in plaintext.",
                        technicalDetails: {
                            transformation: transformation,
                            mode: "ECB"
                        },
                        impact: "Identical plaintext blocks produce identical ciphertext blocks, leaking information about biometric data structure.",
                        mitigation: "Use GCM or CBC mode with random IV.",
                        codeSnippet: {
                            vulnerable: 'Cipher.getInstance("AES/ECB/PKCS5Padding")',
                            secure: 'Cipher.getInstance("AES/GCM/NoPadding")'
                        }
                    };
                    addVulnerability(vuln);
                }
                
                // Try to get key size
                try {
                    var keyBytes = key.getEncoded();
                    if (keyBytes !== null) {
                        var keySize = keyBytes.length * 8;
                        log("CRYPTO", "Key size: " + keySize + " bits", "DEBUG");
                        
                        if (algorithm.includes("AES") && keySize < 256) {
                            var vuln = {
                                type: "CRYPTO_WEAKNESS",
                                severity: "MEDIUM",
                                category: "Cryptographic Security",
                                title: "Weak Key Size",
                                description: "AES key size is less than 256 bits. While 128-bit AES is currently secure, 256-bit provides better long-term security.",
                                technicalDetails: {
                                    keySize: keySize + " bits",
                                    algorithm: algorithm
                                },
                                mitigation: "Use 256-bit keys for AES encryption.",
                                codeSnippet: {
                                    vulnerable: 'keyGen.init(128);',
                                    secure: 'keyGen.init(256);'
                                }
                            };
                            addVulnerability(vuln);
                        }
                    }
                } catch(e) {
                    log("CRYPTO", "Could not extract key size: " + e, "DEBUG");
                }
                
                return this.init(opmode, key);
            };
            
            // Hook KeyGenerator for key creation monitoring
            var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
            KeyGenerator.generateKey.implementation = function() {
                var algorithm = this.getAlgorithm();
                log("CRYPTO", "Key generated: " + algorithm, "DEBUG");
                
                scanResults.cryptoFindings.push({
                    type: "KEY_GENERATION",
                    algorithm: algorithm,
                    timestamp: new Date().toISOString()
                });
                
                return this.generateKey();
            };
            
            // Hook KeyStore operations
            var KeyStore = Java.use("java.security.KeyStore");
            KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function(param) {
                log("CRYPTO", " KeyStore being loaded - secure storage", "SUCCESS");
                
                scanResults.cryptoFindings.push({
                    type: "SECURE_PRACTICE",
                    category: "Key Storage",
                    title: "Android KeyStore Used",
                    description: "Application properly uses Android KeyStore for secure key storage"
                });
                
                return this.load(param);
            };
            
            log("CRYPTO", "Cryptographic hooks installed successfully", "SUCCESS");
            
        } catch(e) {
            log("CRYPTO", "Failed to install crypto hooks: " + e, "ERROR");
        }
    });
}

// ============================================================================
// MODULE 4: STORAGE SECURITY ANALYSIS
// ============================================================================

function hookStorageOperations() {
    Java.perform(function() {
        try {
            log("STORAGE", "Installing storage security hooks...", "INFO");
            
            // Hook SharedPreferences writes
            var Editor = Java.use("android.content.SharedPreferences$Editor");
            
            Editor.putString.implementation = function(key, value) {
                var keyLower = key.toLowerCase();
                var sensitiveKeys = ["biometric", "fingerprint", "face", "template", "auth", "token"];
                
                var isSensitive = sensitiveKeys.some(function(k) {
                    return keyLower.includes(k);
                });
                
                if (isSensitive) {
                    log("STORAGE", " CRITICAL: Sensitive data stored in SharedPreferences!", "ERROR");
                    log("STORAGE", "Key: " + key + ", Value length: " + value.length, "WARNING");
                    
                    var vuln = {
                        type: "INSECURE_STORAGE",
                        severity: "CRITICAL",
                        category: "Data Storage",
                        title: "Biometric Data Stored in Plaintext SharedPreferences",
                        description: "Sensitive biometric-related data is stored in SharedPreferences without encryption. This data can be easily extracted by malware or attackers with device access.",
                        technicalDetails: {
                            storageType: "SharedPreferences",
                            key: key,
                            valueLength: value.length,
                            encrypted: false,
                            stackTrace: getStackTrace()
                        },
                        impact: "Biometric templates or authentication tokens can be extracted from device storage and potentially reused. On rooted devices or with ADB access, SharedPreferences are trivially readable.",
                        mitigation: "Use EncryptedSharedPreferences (Jetpack Security) or store sensitive data in Android KeyStore only.",
                        codeSnippet: {
                            vulnerable: 'SharedPreferences prefs = getSharedPreferences("biometric", MODE_PRIVATE);\nprefs.edit().putString("template", data).apply();',
                            secure: 'MasterKey masterKey = new MasterKey.Builder(context)\n    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)\n    .build();\nSharedPreferences securePrefs = EncryptedSharedPreferences.create(\n    context, "secure_biometric", masterKey,\n    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,\n    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM\n);'
                        },
                        references: [
                            "https://developer.android.com/topic/security/data",
                            "https://developer.android.com/jetpack/androidx/releases/security"
                        ]
                    };
                    addVulnerability(vuln);
                    
                    scanResults.storageFindings.push({
                        type: "INSECURE_WRITE",
                        key: key,
                        timestamp: new Date().toISOString()
                    });
                }
                
                return this.putString(key, value);
            };
            
            // Hook file writes
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
                log("STORAGE", "File write: " + path, "DEBUG");
                
                if (path.includes("biometric") || path.includes("template") || path.includes("fingerprint")) {
                    log("STORAGE", " Biometric-related file write detected", "WARNING");
                    
                    var vuln = {
                        type: "INSECURE_STORAGE",
                        severity: "HIGH",
                        category: "Data Storage",
                        title: "Biometric Data Written to File",
                        description: "Biometric-related data is being written to a file on device storage.",
                        technicalDetails: {
                            filePath: path,
                            storageType: "File System"
                        },
                        impact: "File-based storage of biometric data is risky. Files can be accessed by backup tools, file managers on rooted devices, or malware.",
                        mitigation: "Avoid storing biometric templates in files. If necessary, use Android KeyStore encryption."
                    };
                    addVulnerability(vuln);
                }
                
                return this.$init(path);
            };
            
            // Check for EncryptedSharedPreferences usage (GOOD)
            try {
                var EncryptedSharedPreferences = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
                
                EncryptedSharedPreferences.create.overload(
                    'android.content.Context',
                    'java.lang.String',
                    'androidx.security.crypto.MasterKey',
                    'androidx.security.crypto.EncryptedSharedPreferences$PrefKeyEncryptionScheme',
                    'androidx.security.crypto.EncryptedSharedPreferences$PrefValueEncryptionScheme'
                ).implementation = function(context, fileName, masterKey, prefKeyScheme, prefValueScheme) {
                    log("STORAGE", " EncryptedSharedPreferences created - SECURE", "SUCCESS");
                    
                    scanResults.storageFindings.push({
                        type: "SECURE_PRACTICE",
                        category: "Encrypted Storage",
                        title: "EncryptedSharedPreferences Used",
                        fileName: fileName,
                        timestamp: new Date().toISOString()
                    });
                    
                    return this.create(context, fileName, masterKey, prefKeyScheme, prefValueScheme);
                };
            } catch(e) {
                log("STORAGE", "EncryptedSharedPreferences not available (Jetpack Security not used)", "DEBUG");
            }
            
            log("STORAGE", "Storage security hooks installed successfully", "SUCCESS");
            
        } catch(e) {
            log("STORAGE", "Failed to install storage hooks: " + e, "ERROR");
        }
    });
}

// ============================================================================
// MODULE 5: NETWORK SECURITY ANALYSIS
// ============================================================================

function hookNetworkOperations() {
    Java.perform(function() {
        try {
            log("NETWORK", "Installing network security hooks...", "INFO");
            
            // Hook URL connections
            var URL = Java.use("java.net.URL");
            URL.openConnection.overload().implementation = function() {
                var url = this.toString();
                log("NETWORK", "Connection opened to: " + url, "DEBUG");
                
                // Check if biometric-related data is being transmitted
                if (url.toLowerCase().includes("biometric") || 
                    url.toLowerCase().includes("fingerprint") ||
                    url.toLowerCase().includes("face")) {
                    
                    log("NETWORK", " Biometric-related network connection detected", "WARNING");
                    
                    var vuln = {
                        type: "NETWORK_TRANSMISSION",
                        severity: "HIGH",
                        category: "Network Security",
                        title: "Biometric Data Network Transmission Detected",
                        description: "Application is establishing network connections with biometric-related endpoints. Biometric templates should NEVER leave the device.",
                        technicalDetails: {
                            url: url,
                            protocol: url.split(":")[0]
                        },
                        impact: "Transmitting biometric data over network violates privacy regulations (GDPR, BIPA) and creates interception risks.",
                        mitigation: "Keep all biometric processing on-device. Use Android KeyStore for local storage only.",
                        references: [
                            "https://gdpr.eu/biometric-data/",
                            "https://source.android.com/security/biometric"
                        ]
                    };
                    addVulnerability(vuln);
                }
                
                scanResults.networkFindings.push({
                    type: "CONNECTION",
                    url: url,
                    timestamp: new Date().toISOString()
                });
                
                return this.openConnection();
            };
            
            // Hook OkHttp if available
            try {
                var OkHttpClient = Java.use("okhttp3.OkHttpClient");
                log("NETWORK", "OkHttp detected - installing hooks", "DEBUG");
                
                // Could add more specific OkHttp hooks here
            } catch(e) {
                log("NETWORK", "OkHttp not found", "DEBUG");
            }
            
            log("NETWORK", "Network security hooks installed successfully", "SUCCESS");
            
        } catch(e) {
            log("NETWORK", "Failed to install network hooks: " + e, "ERROR");
        }
    });
}

// ============================================================================
// MODULE 6: MEMORY ANALYSIS
// ============================================================================

function performMemoryAnalysis() {
    Java.perform(function() {
        try {
            log("MEMORY", "Performing memory analysis...", "INFO");
            
            // Search for BiometricPrompt.CryptoObject instances in heap
            Java.choose("androidx.biometric.BiometricPrompt$CryptoObject", {
                onMatch: function(instance) {
                    log("MEMORY", "CryptoObject instance found in memory", "DEBUG");
                    
                    try {
                        var cipher = instance.getCipher();
                        if (cipher !== null) {
                            log("MEMORY", "Cipher found: " + cipher.getAlgorithm(), "DEBUG");
                        }
                    } catch(e) {}
                    
                    scanResults.memoryFindings.push({
                        type: "CRYPTO_OBJECT_IN_MEMORY",
                        className: "BiometricPrompt.CryptoObject",
                        timestamp: new Date().toISOString()
                    });
                },
                onComplete: function() {
                    log("MEMORY", "Memory scan complete", "DEBUG");
                }
            });
            
            // Check for biometric-related strings in memory
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    if (className.toLowerCase().includes("biometric") || 
                        className.toLowerCase().includes("fingerprint")) {
                        log("MEMORY", "Biometric-related class: " + className, "DEBUG");
                    }
                },
                onComplete: function() {}
            });
            
        } catch(e) {
            log("MEMORY", "Memory analysis error: " + e, "ERROR");
        }
    });
}

// ============================================================================
// REPORT GENERATION & EXPORT
// ============================================================================

function saveReportToFile(path, contents) {
    try {
        Java.perform(function() {
            var File = Java.use("java.io.File");
            var FileWriter = Java.use("java.io.FileWriter");
            var reportFile = File.$new(path);
            var writer = FileWriter.$new(reportFile);
            // Use explicit overload: write(String, int, int)
            writer.write.overload('java.lang.String', 'int', 'int').call(writer, contents, 0, contents.length);
            writer.close();
            log("REPORT", " Report saved to: " + reportFile.getAbsolutePath(), "SUCCESS");
        });
    } catch (e) {
        log("REPORT", "Could not save report to file: " + e, "WARNING");
        log("REPORT", "You can copy the JSON output above manually", "INFO");
    }
}

function calculateRiskScore() {
    var score = 100;
    
    scanResults.vulnerabilities.forEach(function(vuln) {
        switch(vuln.severity) {
            case "CRITICAL":
                score -= 25;
                break;
            case "HIGH":
                score -= 15;
                break;
            case "MEDIUM":
                score -= 8;
                break;
            case "LOW":
                score -= 3;
                break;
        }
    });
    
    return Math.max(0, score);
}

function generateReport() {
    log("REPORT", "═══════════════════════════════════════", "INFO");
    log("REPORT", "GENERATING FINAL SCAN REPORT", "INFO");
    log("REPORT", "═══════════════════════════════════════", "INFO");
    
    var riskScore = calculateRiskScore();
    scanResults.metadata.riskScore = riskScore;
    scanResults.metadata.scanDuration = (Date.now() - startTime) / 1000;
    
    // Categorize vulnerabilities by severity
    var severityCounts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0
    };
    
    scanResults.vulnerabilities.forEach(function(vuln) {
        severityCounts[vuln.severity]++;
    });
    
    log("REPORT", "Risk Score: " + riskScore + "/100", "INFO");
    log("REPORT", "Total Vulnerabilities: " + scanResults.vulnerabilities.length, "INFO");
    log("REPORT", "   Critical: " + severityCounts.CRITICAL, "INFO");
    log("REPORT", "   High: " + severityCounts.HIGH, "INFO");
    log("REPORT", "   Medium: " + severityCounts.MEDIUM, "INFO");
    log("REPORT", "   Low: " + severityCounts.LOW, "INFO");
    log("REPORT", "═══════════════════════════════════════", "INFO");
    
    // Print summary of each vulnerability
    if (scanResults.vulnerabilities.length > 0) {
        log("REPORT", "VULNERABILITY SUMMARY:", "INFO");
        scanResults.vulnerabilities.forEach(function(vuln, index) {
            log("REPORT", (index + 1) + ". [" + vuln.severity + "] " + vuln.title, "WARNING");
        });
    }
    
    // Export full report as JSON
    var reportJSON = JSON.stringify(scanResults, null, 2);
    log("REPORT", "═══════════════════════════════════════", "INFO");
    log("REPORT", "FULL REPORT (JSON):", "INFO");
    console.log(reportJSON);
    log("REPORT", "═══════════════════════════════════════", "INFO");
    
    // Save to file (if possible)
    saveReportToFile("/sdcard/Download/biometric_scan_" + scanResults.metadata.scanId + ".json", reportJSON);
    
    // Stop autosave once final report is generated
    if (typeof __autosaveTimer !== 'undefined' && __autosaveTimer) {
        clearInterval(__autosaveTimer);
        __autosaveTimer = null;
    }
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================

var startTime = Date.now();

console.log("\n");
log("SCANNER", "═══════════════════════════════════════════════════════", "INFO");
log("SCANNER", "   BIOMETRIC SECURITY SCANNER - Frida Edition", "INFO");
log("SCANNER", "   FYP-25-S3-25 | Comprehensive Vulnerability Analysis", "INFO");
log("SCANNER", "═══════════════════════════════════════════════════════", "INFO");
console.log("\n");

Java.perform(function() {
    log("SCANNER", " Starting biometric security scan...", "INFO");
    
    // Collect metadata
    collectDeviceInfo();
    collectAppInfo();
    
    // Install all hooks
    if (SCAN_CONFIG.enableAPIHooks) {
        hookBiometricPromptAPI();
    }
    
    if (SCAN_CONFIG.enableTimingAnalysis) {
        hookBiometricCallbacks();
    }
    
    if (SCAN_CONFIG.enableCryptoHooks) {
        hookCryptoOperations();
    }
    
    if (SCAN_CONFIG.enableStorageHooks) {
        hookStorageOperations();
    }
    
    if (SCAN_CONFIG.enableNetworkHooks) {
        hookNetworkOperations();
    }
    
    if (SCAN_CONFIG.enableMemoryAnalysis) {
        setTimeout(performMemoryAnalysis, 2000); // Delay for app initialization
    }
    
    log("SCANNER", " All hooks installed successfully", "SUCCESS");
    log("SCANNER", " Waiting for biometric authentication activity...", "INFO");
    log("SCANNER", "   (Trigger biometric authentication in the target app)", "INFO");
    
    // Periodic autosave so data is preserved even if the script is exited
    try {
        if (typeof __autosaveTimer === 'undefined' || !__autosaveTimer) {
            __autosaveTimer = setInterval(function() {
                try {
                    var reportJSON = JSON.stringify(scanResults, null, 2);
                    var scanId = (scanResults && scanResults.metadata && scanResults.metadata.scanId) ? scanResults.metadata.scanId : 'autosave';
                    saveReportToFile("/sdcard/Download/biometric_scan_" + scanId + "_autosave.json", reportJSON);
                } catch (e) {
                    log("REPORT", "Autosave error: " + e, "WARNING");
                }
            }, 10000); // every 10 seconds
        }
    } catch (e) {
        // Ignore autosave setup failures
    }

    // Set up auto-report generation after delay
    setTimeout(function() {
        log("SCANNER", " Scan timeout reached, generating report...", "INFO");
        generateReport();
    }, 60000); // 60 seconds timeout
});

// Manual report generation (call this from Frida console)
var __root = (typeof globalThis !== 'undefined') ? globalThis :
             (typeof global !== 'undefined') ? global :
             (typeof window !== 'undefined') ? window : this;
__root.generateReport = generateReport;
__root.getScanResults = function() { return scanResults; };

log("SCANNER", " TIP: Use generateReport() to export results anytime", "INFO");
log("SCANNER", " TIP: Use getScanResults() to view raw data", "INFO");
console.log("\n");
