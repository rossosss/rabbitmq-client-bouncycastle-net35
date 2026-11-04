using System.Collections;
using System.Net;
using Org.BouncyCastle.Crypto.Tls;

namespace RabbitMQ.Client.Impl
{
    internal sealed class BouncyCastleTlsClient : DefaultTlsClient
    {
        private readonly SslOption m_sslOption;
        private readonly string m_serverName;

        internal BouncyCastleTlsClient(SslOption sslOption, string serverName)
        {
            m_sslOption = sslOption;
            IPAddress address;
            m_serverName = IPAddress.TryParse(serverName.Trim('[', ']'), out address)
                ? serverName
                : BouncyCastleCertificateValidator.NormalizeDnsName(serverName);
        }

        public override ProtocolVersion ClientVersion
        {
            get { return ProtocolVersion.TLSv12; }
        }

        public override ProtocolVersion MinimumVersion
        {
            get { return ProtocolVersion.TLSv12; }
        }

        public override IDictionary GetClientExtensions()
        {
            IDictionary extensions = base.GetClientExtensions();
            IPAddress address;
            if (IPAddress.TryParse(m_serverName.Trim('[', ']'), out address))
            {
                return extensions;
            }

            extensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(extensions);
            ArrayList serverNames = new ArrayList();
            serverNames.Add(new ServerName(NameType.host_name, m_serverName));
            TlsExtensionsUtilities.AddServerNameExtension(extensions, new ServerNameList(serverNames));
            return extensions;
        }

        public override TlsAuthentication GetAuthentication()
        {
            return new BouncyCastleTlsAuthentication(mContext, m_sslOption, m_serverName);
        }
    }
}
