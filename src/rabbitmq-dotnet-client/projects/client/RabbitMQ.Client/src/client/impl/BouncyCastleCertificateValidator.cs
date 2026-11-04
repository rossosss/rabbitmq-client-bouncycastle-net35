using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;
using BouncyCastleCertificate = Org.BouncyCastle.X509.X509Certificate;
using TlsCertificate = Org.BouncyCastle.Crypto.Tls.Certificate;

namespace RabbitMQ.Client.Impl
{
    internal static class BouncyCastleCertificateValidator
    {
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
        private const string AnyExtendedKeyUsageOid = "2.5.29.37.0";

        internal static void Validate(TlsCertificate serverCertificate, string serverName, SslOption sslOption)
        {
            if (serverCertificate == null || serverCertificate.IsEmpty)
            {
                throw new IOException("The TLS server did not provide a certificate.");
            }

            X509CertificateStructure[] structures = serverCertificate.GetCertificateList();
            BouncyCastleCertificate[] certificates = new BouncyCastleCertificate[structures.Length];
            for (int i = 0; i < structures.Length; i++)
            {
                certificates[i] = new BouncyCastleCertificate(structures[i]);
            }

            SslPolicyErrors errors = SslPolicyErrors.None;
            Exception chainError = null;
            Exception nameError = null;

            try
            {
                ValidateChain(certificates, sslOption.TrustStorePath);
            }
            catch (Exception e)
            {
                errors |= SslPolicyErrors.RemoteCertificateChainErrors;
                chainError = e;
            }

            try
            {
                if (!MatchesHostName(certificates[0], serverName))
                {
                    throw new CertificateException("The server certificate does not match '" + serverName + "'.");
                }
            }
            catch (Exception e)
            {
                errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
                nameError = e;
            }

            if (sslOption.CertificateValidationCallback != null)
            {
                System.Security.Cryptography.X509Certificates.X509Certificate2 certificate =
                    new System.Security.Cryptography.X509Certificates.X509Certificate2(certificates[0].GetEncoded());
                bool accepted = sslOption.CertificateValidationCallback(sslOption, certificate, null, errors);
                if (!accepted)
                {
                    throw new IOException("The server certificate was rejected by the validation callback.");
                }
                return;
            }

            SslPolicyErrors rejected = errors & ~sslOption.AcceptablePolicyErrors;
            if (rejected != SslPolicyErrors.None)
            {
                string message = "The server certificate validation failed: " + rejected + ".";
                Exception cause = chainError ?? nameError;
                throw new IOException(message, cause);
            }
        }

        internal static void ValidateChain(BouncyCastleCertificate[] certificates, string trustStorePath)
        {
            if (certificates == null || certificates.Length == 0)
            {
                throw new ArgumentException("A server certificate chain is required.", "certificates");
            }

            BouncyCastleCertificate leaf = certificates[0];
            leaf.CheckValidity();

            IList extendedKeyUsage = leaf.GetExtendedKeyUsage();
            if (extendedKeyUsage != null && !extendedKeyUsage.Contains(ServerAuthOid) &&
                !extendedKeyUsage.Contains(AnyExtendedKeyUsageOid))
            {
                throw new CertificateException("The server certificate is not valid for TLS server authentication.");
            }

            if (String.IsNullOrEmpty(trustStorePath))
            {
                throw new InvalidOperationException("SslOption.TrustStorePath must specify a PEM or DER CA certificate file.");
            }

            ICollection parsed;
            using (Stream input = File.OpenRead(trustStorePath))
            {
                parsed = new X509CertificateParser().ReadCertificates(input);
            }
            if (parsed.Count == 0)
            {
                throw new CertificateException("The trust store does not contain any certificates.");
            }

            ArrayList trustedCertificates = new ArrayList();
            HashSet trustAnchors = new HashSet();
            foreach (BouncyCastleCertificate certificate in parsed)
            {
                trustedCertificates.Add(certificate);
                trustAnchors.Add(new TrustAnchor(certificate, null));
            }

            ArrayList pathCertificates = new ArrayList();
            foreach (BouncyCastleCertificate certificate in certificates)
            {
                if (!trustedCertificates.Contains(certificate))
                {
                    pathCertificates.Add(certificate);
                }
            }

            if (pathCertificates.Count == 0)
            {
                if (certificates.Length == 1 && trustedCertificates.Contains(certificates[0]))
                {
                    return;
                }
                throw new CertificateException("The server certificate path is empty.");
            }

            ArrayList storeCertificates = new ArrayList();
            foreach (BouncyCastleCertificate certificate in certificates)
            {
                storeCertificates.Add(certificate);
            }
            foreach (BouncyCastleCertificate certificate in trustedCertificates)
            {
                storeCertificates.Add(certificate);
            }

            PkixParameters parameters = new PkixParameters(trustAnchors);
            parameters.IsRevocationEnabled = false;
            parameters.AddStore(X509StoreFactory.Create("CERTIFICATE/COLLECTION",
                new X509CollectionStoreParameters(storeCertificates)));
            new PkixCertPathValidator().Validate(new PkixCertPath(pathCertificates), parameters);
        }

        internal static bool MatchesHostName(BouncyCastleCertificate certificate, string serverName)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException("certificate");
            }
            if (String.IsNullOrEmpty(serverName))
            {
                throw new ArgumentException("A TLS server name is required.", "serverName");
            }

            IPAddress address;
            if (IPAddress.TryParse(serverName.Trim('[', ']'), out address))
            {
                return MatchesIpAddress(certificate, address);
            }
            return MatchesDnsName(certificate, serverName);
        }

        private static bool MatchesIpAddress(BouncyCastleCertificate certificate, IPAddress address)
        {
            GeneralNames names = GetSubjectAlternativeNames(certificate);
            if (names == null)
            {
                return false;
            }

            byte[] expected = address.GetAddressBytes();
            foreach (GeneralName name in names.GetNames())
            {
                if (name.TagNo != GeneralName.IPAddress)
                {
                    continue;
                }

                Asn1OctetString encodedAddress = name.Name as Asn1OctetString;
                if (encodedAddress == null)
                {
                    continue;
                }

                byte[] actual = encodedAddress.GetOctets();
                if (actual.Length != expected.Length)
                {
                    continue;
                }

                bool match = true;
                for (int i = 0; i < expected.Length; i++)
                {
                    match &= actual[i] == expected[i];
                }
                if (match)
                {
                    return true;
                }
            }

            return false;
        }

        private static bool MatchesDnsName(BouncyCastleCertificate certificate, string hostName)
        {
            string normalizedHost = NormalizeDnsName(hostName);
            GeneralNames names = GetSubjectAlternativeNames(certificate);
            bool hasDnsName = false;

            if (names != null)
            {
                foreach (GeneralName name in names.GetNames())
                {
                    if (name.TagNo != GeneralName.DnsName)
                    {
                        continue;
                    }

                    hasDnsName = true;
                    IAsn1String dnsName = name.Name as IAsn1String;
                    if (dnsName != null && MatchesDnsPattern(dnsName.GetString(), normalizedHost))
                    {
                        return true;
                    }
                }
            }

            if (hasDnsName)
            {
                return false;
            }

            IList commonNames = certificate.SubjectDN.GetValueList(X509Name.CN);
            for (int i = commonNames.Count - 1; i >= 0; i--)
            {
                string commonName = commonNames[i] as string;
                if (commonName != null && MatchesDnsPattern(commonName, normalizedHost))
                {
                    return true;
                }
            }

            return false;
        }

        private static GeneralNames GetSubjectAlternativeNames(BouncyCastleCertificate certificate)
        {
            Asn1OctetString extension = certificate.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (extension == null)
            {
                return null;
            }
            return GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(extension));
        }

        private static bool MatchesDnsPattern(string pattern, string normalizedHost)
        {
            if (String.IsNullOrEmpty(pattern))
            {
                return false;
            }

            bool wildcard = pattern.StartsWith("*.", StringComparison.Ordinal);
            string normalizedPattern = wildcard
                ? "*." + NormalizeDnsName(pattern.Substring(2))
                : NormalizeDnsName(pattern);

            if (!wildcard)
            {
                return normalizedPattern.IndexOf('*') < 0 && normalizedPattern == normalizedHost;
            }

            string suffix = normalizedPattern.Substring(1);
            if (!normalizedHost.EndsWith(suffix, StringComparison.Ordinal))
            {
                return false;
            }

            string firstLabel = normalizedHost.Substring(0, normalizedHost.Length - suffix.Length);
            return firstLabel.Length > 0 && firstLabel.IndexOf('.') < 0;
        }

        internal static string NormalizeDnsName(string name)
        {
            string normalized = name.Trim();
            if (normalized.EndsWith(".", StringComparison.Ordinal))
            {
                normalized = normalized.Substring(0, normalized.Length - 1);
            }
            if (normalized.Length == 0)
            {
                throw new ArgumentException("A DNS name cannot be empty.", "name");
            }
            return new IdnMapping().GetAscii(normalized).ToLowerInvariant();
        }
    }
}
