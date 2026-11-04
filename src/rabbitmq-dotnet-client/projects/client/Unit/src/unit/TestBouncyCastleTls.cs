// This source code is dual-licensed under the Apache License, version
// 2.0, and the Mozilla Public License, version 1.1.
//
// The APL v2.0:
//
//---------------------------------------------------------------------------
//   Copyright (C) 2007-2014 GoPivotal, Inc.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//---------------------------------------------------------------------------
//
// The MPL v1.1:
//
//---------------------------------------------------------------------------
//  The contents of this file are subject to the Mozilla Public License
//  Version 1.1 (the "License"); you may not use this file except in
//  compliance with the License. You may obtain a copy of the License
//  at http://www.mozilla.org/MPL/
//
//  Software distributed under the License is distributed on an "AS IS"
//  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
//  the License for the specific language governing rights and
//  limitations under the License.
//
//  The Original Code is RabbitMQ.
//
//  The Initial Developer of the Original Code is GoPivotal, Inc.
//  Copyright (c) 2007-2014 GoPivotal, Inc.  All rights reserved.
//---------------------------------------------------------------------------

using System;
using System.Collections;
using System.IO;
using NUnit.Framework;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using RabbitMQ.Client.Impl;
using BouncyCastleCertificate = Org.BouncyCastle.X509.X509Certificate;
using TlsCertificate = Org.BouncyCastle.Crypto.Tls.Certificate;

namespace RabbitMQ.Client.Unit
{
    [TestFixture]
    public class TestBouncyCastleTls
    {
        private const string Pkcs12Password = "test-password";
        private static readonly SecureRandom Random = new SecureRandom();

        [Test]
        public void AcceptsValidServerCertificate()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "localhost", DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPServerAuth);

            ValidateServer(server.Certificate, authority.Certificate, "localhost");
        }

        [Test]
        public void RejectsWrongCa()
        {
            TestAuthority issuer = CreateAuthority("CN=Issuer CA", false);
            TestAuthority trusted = CreateAuthority("CN=Other CA", false);
            TestCredential server = CreateLeaf(issuer, false, "localhost", DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPServerAuth);

            AssertValidationFails(server.Certificate, trusted.Certificate, "localhost");
        }

        [Test]
        public void RejectsWrongHostName()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "wrong.example.com", DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPServerAuth);

            AssertValidationFails(server.Certificate, authority.Certificate, "localhost");
        }

        [Test]
        public void RejectsExpiredCertificate()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "localhost", DateTime.UtcNow.AddDays(-10),
                DateTime.UtcNow.AddDays(-5), KeyPurposeID.IdKPServerAuth);

            AssertValidationFails(server.Certificate, authority.Certificate, "localhost");
        }

        [Test]
        public void RejectsNotYetValidCertificate()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "localhost", DateTime.UtcNow.AddDays(5),
                DateTime.UtcNow.AddDays(10), KeyPurposeID.IdKPServerAuth);

            AssertValidationFails(server.Certificate, authority.Certificate, "localhost");
        }

        [Test]
        public void RejectsCertificateWithoutServerAuth()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "localhost", DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);

            AssertValidationFails(server.Certificate, authority.Certificate, "localhost");
        }

        [Test]
        public void RejectsUntrustedSelfSignedCertificate()
        {
            TestAuthority trusted = CreateAuthority("CN=Trusted CA", false);
            AsymmetricCipherKeyPair serverKeys = CreateKeyPair(false);
            BouncyCastleCertificate server = CreateCertificate(new X509Name("CN=localhost"), serverKeys.Public,
                new X509Name("CN=localhost"), serverKeys.Private, false, "localhost", DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPServerAuth);

            AssertValidationFails(server, trusted.Certificate, "localhost");
        }

        [Test]
        public void AcceptsInternationalHostNameAsPunycode()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential server = CreateLeaf(authority, false, "xn--e1afmkfd.xn--p1ai",
                DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPServerAuth);

            ValidateServer(server.Certificate, authority.Certificate, "пример.рф");
        }

        [Test]
        public void SendsInternationalSniAsPunycode()
        {
            BouncyCastleTlsClient client = new BouncyCastleTlsClient(new SslOption(), "пример.рф");
            client.Init(new TestTlsClientContext());
            ServerNameList serverNames = TlsExtensionsUtilities.GetServerNameExtension(client.GetClientExtensions());

            Assert.IsNotNull(serverNames);
            Assert.AreEqual(1, serverNames.ServerNames.Count);
            ServerName serverName = (ServerName)serverNames.ServerNames[0];
            Assert.AreEqual("xn--e1afmkfd.xn--p1ai", serverName.GetHostName());
        }

        [Test]
        public void DoesNotSendSniForIpAddress()
        {
            BouncyCastleTlsClient client = new BouncyCastleTlsClient(new SslOption(), "127.0.0.1");
            client.Init(new TestTlsClientContext());

            Assert.IsNull(TlsExtensionsUtilities.GetServerNameExtension(client.GetClientExtensions()));
        }

        [Test]
        public void SelectsClientCertificateFromRequestedCa()
        {
            TestAuthority wrongAuthority = CreateAuthority("CN=Wrong CA", false);
            TestAuthority rightAuthority = CreateAuthority("CN=Right CA", false);
            TestCredential wrong = CreateLeaf(wrongAuthority, false, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);
            TestCredential right = CreateLeaf(rightAuthority, false, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);
            ArrayList authorities = new ArrayList();
            authorities.Add(rightAuthority.Name);

            TlsCredentials credentials = SelectCredentials(wrong, right,
                new byte[] { ClientCertificateType.rsa_sign }, SignatureAlgorithms(SignatureAlgorithm.rsa), authorities);

            AssertSelectedCertificate(credentials, right.Certificate);
        }

        [Test]
        public void ContinuesAfterCredentialWithIncompatibleSignature()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential wrong = CreateLeaf(authority, true, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);
            TestCredential right = CreateLeaf(authority, false, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);

            TlsCredentials credentials = SelectCredentials(wrong, right,
                new byte[] { ClientCertificateType.rsa_sign, ClientCertificateType.ecdsa_sign },
                SignatureAlgorithms(SignatureAlgorithm.rsa), null);

            AssertSelectedCertificate(credentials, right.Certificate);
        }

        [Test]
        public void SelectsEcdsaCredentialWhenRequested()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential wrong = CreateLeaf(authority, false, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);
            TestCredential right = CreateLeaf(authority, true, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);
            ArrayList algorithms = SignatureAlgorithms(SignatureAlgorithm.rsa);
            algorithms.Add(new SignatureAndHashAlgorithm(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa));

            TlsCredentials credentials = SelectCredentials(wrong, right,
                new byte[] { ClientCertificateType.ecdsa_sign }, algorithms, null);

            AssertSelectedCertificate(credentials, right.Certificate);
        }

        [Test]
        public void ReturnsNoCredentialWhenNothingMatches()
        {
            TestAuthority authority = CreateAuthority("CN=Test CA", false);
            TestCredential clientCertificate = CreateLeaf(authority, true, null, DateTime.UtcNow.AddDays(-1),
                DateTime.UtcNow.AddDays(1), KeyPurposeID.IdKPClientAuth);

            TlsCredentials credentials = SelectCredentials(clientCertificate, null,
                new byte[] { ClientCertificateType.rsa_sign }, SignatureAlgorithms(SignatureAlgorithm.rsa), null);

            Assert.IsNull(credentials);
        }

        private static ArrayList SignatureAlgorithms(byte signatureAlgorithm)
        {
            ArrayList algorithms = new ArrayList();
            algorithms.Add(new SignatureAndHashAlgorithm(HashAlgorithm.sha256, signatureAlgorithm));
            return algorithms;
        }

        private static TlsCredentials SelectCredentials(TestCredential first, TestCredential second,
            byte[] certificateTypes, IList signatureAlgorithms, IList certificateAuthorities)
        {
            Pkcs12Store store = new Pkcs12Store();
            AddCredential(store, "first", first);
            if (second != null)
            {
                AddCredential(store, "second", second);
            }

            string path = Path.GetTempFileName();
            try
            {
                using (FileStream output = File.Create(path))
                {
                    store.Save(output, Pkcs12Password.ToCharArray(), Random);
                }

                SslOption options = new SslOption("localhost", path, true);
                options.CertPassphrase = Pkcs12Password;
                CertificateRequest request = new CertificateRequest(certificateTypes, signatureAlgorithms,
                    certificateAuthorities);
                return new BouncyCastleTlsAuthentication(new TestTlsClientContext(), options, "localhost")
                    .GetClientCredentials(request);
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static void AddCredential(Pkcs12Store store, string alias, TestCredential credential)
        {
            store.SetKeyEntry(alias, new AsymmetricKeyEntry(credential.Keys.Private), credential.Chain);
        }

        private static void AssertSelectedCertificate(TlsCredentials credentials,
            BouncyCastleCertificate expectedCertificate)
        {
            Assert.IsNotNull(credentials);
            X509CertificateStructure structure = credentials.Certificate.GetCertificateList()[0];
            Assert.AreEqual(expectedCertificate, new BouncyCastleCertificate(structure));
        }

        private static void AssertValidationFails(BouncyCastleCertificate server, BouncyCastleCertificate trusted,
            string serverName)
        {
            Assert.Throws(Is.InstanceOf<IOException>(), delegate { ValidateServer(server, trusted, serverName); });
        }

        private static void ValidateServer(BouncyCastleCertificate server, BouncyCastleCertificate trusted,
            string serverName)
        {
            string trustStorePath = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(trustStorePath, trusted.GetEncoded());
                SslOption options = new SslOption();
                options.TrustStorePath = trustStorePath;
                TlsCertificate certificate = new TlsCertificate(
                    new X509CertificateStructure[] { server.CertificateStructure });
                BouncyCastleCertificateValidator.Validate(certificate, serverName, options);
            }
            finally
            {
                File.Delete(trustStorePath);
            }
        }

        private static TestAuthority CreateAuthority(string name, bool useEcdsa)
        {
            TestAuthority authority = new TestAuthority();
            authority.Name = new X509Name(name);
            authority.Keys = CreateKeyPair(useEcdsa);
            authority.Certificate = CreateCertificate(authority.Name, authority.Keys.Public, authority.Name,
                authority.Keys.Private, true, null, DateTime.UtcNow.AddDays(-2), DateTime.UtcNow.AddDays(30), null);
            return authority;
        }

        private static TestCredential CreateLeaf(TestAuthority authority, bool useEcdsa, string dnsName,
            DateTime notBefore, DateTime notAfter, KeyPurposeID extendedKeyUsage)
        {
            TestCredential credential = new TestCredential();
            credential.Keys = CreateKeyPair(useEcdsa);
            X509Name subject = new X509Name(dnsName == null ? "CN=" + (useEcdsa ? "right" : "wrong") : "CN=" + dnsName);
            credential.Certificate = CreateCertificate(subject, credential.Keys.Public, authority.Name,
                authority.Keys.Private, false, dnsName, notBefore, notAfter, extendedKeyUsage);
            return credential;
        }

        private static AsymmetricCipherKeyPair CreateKeyPair(bool useEcdsa)
        {
            if (useEcdsa)
            {
                ECKeyGenerationParameters parameters = new ECKeyGenerationParameters(
                    SecNamedCurves.GetOid("secp256r1"), Random);
                ECKeyPairGenerator generator = new ECKeyPairGenerator();
                generator.Init(parameters);
                return generator.GenerateKeyPair();
            }

            RsaKeyPairGenerator rsaGenerator = new RsaKeyPairGenerator();
            rsaGenerator.Init(new KeyGenerationParameters(Random, 1024));
            return rsaGenerator.GenerateKeyPair();
        }

        private static BouncyCastleCertificate CreateCertificate(X509Name subject,
            AsymmetricKeyParameter subjectPublicKey, X509Name issuer, AsymmetricKeyParameter issuerPrivateKey,
            bool certificateAuthority, string dnsName, DateTime notBefore, DateTime notAfter,
            KeyPurposeID extendedKeyUsage)
        {
            X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
            generator.SetSerialNumber(BigInteger.ValueOf(DateTime.UtcNow.Ticks));
            generator.SetSubjectDN(subject);
            generator.SetIssuerDN(issuer);
            generator.SetPublicKey(subjectPublicKey);
            generator.SetNotBefore(notBefore);
            generator.SetNotAfter(notAfter);
            ISignatureFactory signatureFactory = new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(
                issuerPrivateKey is ECPrivateKeyParameters ? "SHA256WITHECDSA" : "SHA256WITHRSA",
                issuerPrivateKey, Random);
            generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(certificateAuthority));
            generator.AddExtension(X509Extensions.KeyUsage, true,
                new KeyUsage(certificateAuthority ? KeyUsage.KeyCertSign | KeyUsage.CrlSign : KeyUsage.DigitalSignature));
            if (dnsName != null)
            {
                generator.AddExtension(X509Extensions.SubjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.DnsName, dnsName)));
            }
            if (extendedKeyUsage != null)
            {
                generator.AddExtension(X509Extensions.ExtendedKeyUsage, false,
                    new ExtendedKeyUsage(extendedKeyUsage));
            }
            return generator.Generate(signatureFactory);
        }

        private sealed class TestTlsClientContext : TlsClientContext
        {
            private readonly Org.BouncyCastle.Crypto.Prng.IRandomGenerator m_nonceRandomGenerator =
                new Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator();
            private readonly SecurityParameters m_securityParameters = new SecurityParameters();
            private object m_userObject;

            public Org.BouncyCastle.Crypto.Prng.IRandomGenerator NonceRandomGenerator
            {
                get { return m_nonceRandomGenerator; }
            }

            public SecureRandom SecureRandom
            {
                get { return Random; }
            }

            public SecurityParameters SecurityParameters
            {
                get { return m_securityParameters; }
            }

            public bool IsServer
            {
                get { return false; }
            }

            public ProtocolVersion ClientVersion
            {
                get { return ProtocolVersion.TLSv12; }
            }

            public ProtocolVersion ServerVersion
            {
                get { return ProtocolVersion.TLSv12; }
            }

            public TlsSession ResumableSession
            {
                get { return null; }
            }

            public object UserObject
            {
                get { return m_userObject; }
                set { m_userObject = value; }
            }

            public byte[] ExportKeyingMaterial(string asciiLabel, byte[] contextValue, int length)
            {
                throw new NotSupportedException();
            }
        }

        private sealed class TestAuthority
        {
            internal X509Name Name;
            internal AsymmetricCipherKeyPair Keys;
            internal BouncyCastleCertificate Certificate;
        }

        private sealed class TestCredential
        {
            internal AsymmetricCipherKeyPair Keys;
            internal BouncyCastleCertificate Certificate;
            internal X509CertificateEntry[] Chain
            {
                get { return new X509CertificateEntry[] { new X509CertificateEntry(Certificate) }; }
            }
        }
    }
}
