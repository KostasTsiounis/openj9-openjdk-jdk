/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */

/*
 * @test
 * @summary Test Restricted Security Mode Constraints
 * @library /test/lib
 * @run junit TestConstraints
 */

import java.lang.module.Configuration;
import java.security.AlgorithmParameterGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;
import openj9.internal.security.RestrictedSecurity;

public class TestConstraints {

    private static getInstances() {
        CertificateFactory.getInstance("X.509");
        CertStore.getInstance("Collection");
        Configuration.getInstance("JavaLoginConfig");
        CertPathValidator.getInstance("PKIX");
        MessageDigest.getInstance("SHA-256");
        KeyStore.getInstance("PKCS12");

        Signature.getInstance("SHA256withECDSA");
        KeyPairGenerator.getInstance("EC");
        KeyAgreement.getInstance("ECDH");
        KeyFactory.getInstance("EC");

        Cipher.getInstance("RSA");
        KeyGenerator.getInstance("AES");
        AlgorithmParameterGenerator.getInstance("DiffieHellman");
        KDF.getInstance("HKDF-SHA256");
        SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        Mac.getInstance("HmacSHA256");

        KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory.getInstance("SunX509");
        SSLContext.getInstance("TLSv1.3");
    }

    @Test
    public void runWithConstraints() {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.customprofile=" + RestrictedSecurity.TestConstraints.Version,
                "-Djava.security.properties=" + System.getProperty("test.src") + "/constraints-java.security",
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0);
    }

    public static void main(String[] args) {
        getInstances();
    }
}
