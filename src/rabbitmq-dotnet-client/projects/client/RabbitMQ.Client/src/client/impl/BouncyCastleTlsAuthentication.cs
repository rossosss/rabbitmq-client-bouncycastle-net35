using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using TlsCertificate = Org.BouncyCastle.Crypto.Tls.Certificate;

namespace RabbitMQ.Client.Impl
{
    internal sealed class BouncyCastleTlsAuthentication : TlsAuthentication
    {
        private readonly TlsContext m_context;
        private readonly SslOption m_sslOption;
        private readonly string m_serverName;

        internal BouncyCastleTlsAuthentication(TlsContext context, SslOption sslOption, string serverName)
        {
            m_context = context;
            m_sslOption = sslOption;
            m_serverName = serverName;
        }

        public void NotifyServerCertificate(TlsCertificate serverCertificate)
        {
            BouncyCastleCertificateValidator.Validate(serverCertificate, m_serverName, m_sslOption);
        }

        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            if (String.IsNullOrEmpty(m_sslOption.CertPath))
            {
                if (m_sslOption.Certs != null)
                {
                    throw new NotSupportedException("Bouncy Castle TLS requires the client certificate to be loaded from SslOption.CertPath.");
                }
                return null;
            }

            Pkcs12Store store = new Pkcs12Store();
            using (Stream input = File.OpenRead(m_sslOption.CertPath))
            {
                char[] password = m_sslOption.CertPassphrase == null ? null : m_sslOption.CertPassphrase.ToCharArray();
                store.Load(input, password);
            }

            bool foundPrivateKey = false;
            bool foundCertificate = false;

            foreach (string alias in store.Aliases)
            {
                if (!store.IsKeyEntry(alias))
                {
                    continue;
                }

                foundPrivateKey = true;
                AsymmetricKeyParameter privateKey = store.GetKey(alias).Key;
                X509CertificateEntry[] entries = store.GetCertificateChain(alias);
                if (entries == null)
                {
                    X509CertificateEntry entry = store.GetCertificate(alias);
                    entries = entry == null ? null : new X509CertificateEntry[] { entry };
                }
                if (entries == null || entries.Length == 0)
                {
                    continue;
                }

                foundCertificate = true;
                if (!MatchesCertificateType(certificateRequest.CertificateTypes, privateKey) ||
                    !MatchesCertificateAuthorities(certificateRequest.CertificateAuthorities, entries))
                {
                    continue;
                }

                SignatureAndHashAlgorithm signatureAlgorithm = SelectSignatureAlgorithm(
                    certificateRequest.SupportedSignatureAlgorithms, privateKey);
                if (signatureAlgorithm == null)
                {
                    continue;
                }

                X509CertificateStructure[] structures = new X509CertificateStructure[entries.Length];
                for (int i = 0; i < entries.Length; i++)
                {
                    structures[i] = entries[i].Certificate.CertificateStructure;
                }

                return new DefaultTlsSignerCredentials(m_context, new TlsCertificate(structures), privateKey, signatureAlgorithm);
            }

            if (!foundPrivateKey)
            {
                throw new IOException("The client PKCS#12 file does not contain a private key.");
            }
            if (!foundCertificate)
            {
                throw new IOException("The client PKCS#12 file does not contain a certificate for the private key.");
            }
            return null;
        }

        private static bool MatchesCertificateType(byte[] certificateTypes, AsymmetricKeyParameter privateKey)
        {
            if (certificateTypes == null || certificateTypes.Length == 0)
            {
                return true;
            }

            foreach (byte certificateType in certificateTypes)
            {
                if ((privateKey is RsaKeyParameters && certificateType == ClientCertificateType.rsa_sign) ||
                    (privateKey is DsaPrivateKeyParameters && certificateType == ClientCertificateType.dss_sign) ||
                    (privateKey is ECPrivateKeyParameters && certificateType == ClientCertificateType.ecdsa_sign))
                {
                    return true;
                }
            }

            return false;
        }

        private static bool MatchesCertificateAuthorities(IList certificateAuthorities,
            X509CertificateEntry[] entries)
        {
            if (certificateAuthorities == null || certificateAuthorities.Count == 0)
            {
                return true;
            }

            foreach (X509Name authority in certificateAuthorities)
            {
                foreach (X509CertificateEntry entry in entries)
                {
                    if (authority.Equivalent(entry.Certificate.IssuerDN))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        private static SignatureAndHashAlgorithm SelectSignatureAlgorithm(IList supportedAlgorithms,
            AsymmetricKeyParameter privateKey)
        {
            if (supportedAlgorithms == null)
            {
                return null;
            }

            foreach (SignatureAndHashAlgorithm algorithm in supportedAlgorithms)
            {
                if ((privateKey is RsaKeyParameters && algorithm.Signature == SignatureAlgorithm.rsa) ||
                    (privateKey is DsaPrivateKeyParameters && algorithm.Signature == SignatureAlgorithm.dsa) ||
                    (privateKey is ECPrivateKeyParameters && algorithm.Signature == SignatureAlgorithm.ecdsa))
                {
                    return algorithm;
                }
            }

            return null;
        }
    }
}
