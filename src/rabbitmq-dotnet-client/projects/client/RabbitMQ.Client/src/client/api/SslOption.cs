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
// Modified with settings required by the Bouncy Castle TLS implementation.
//---------------------------------------------------------------------------

using System;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using RabbitMQ.Client.Impl;

namespace RabbitMQ.Client
{
    ///<summary>Represents a configurable SSL option, used
    ///in setting up an SSL connection.</summary>
    public class SslOption
    {

        private bool m_enabled;

        ///<summary>Flag specifying if Ssl should indeed be
        ///used</summary>
        public bool Enabled
        {
            get { return m_enabled; }
            set { m_enabled = value; }
        }


        private SslProtocols m_version = SslProtocols.Tls;

        ///<summary>Legacy protocol setting retained for source compatibility.
        ///The Bouncy Castle transport negotiates TLS 1.2 only.</summary>
        public SslProtocols Version
        {
            get { return m_version; }
            set { m_version = value; }
        }

        private string m_certPath;

        ///<summary>Retrieve or set the path to client certificate.
        ///</summary>
        public string CertPath
        {
            get { return m_certPath; }
            set { m_certPath = value; }
        }

        private string m_certPass;

        ///<summary>Retrieve or set the path to client certificate.
        ///</summary>
        public string CertPassphrase
        {
            get { return m_certPass; }
            set { m_certPass = value; }
        }

        private X509CertificateCollection m_certs;

        ///<summary>Retrieve or set the X509CertificateCollection
        ///containing the client certificate. If no collection is set,
        ///the client will attempt to load one from the specified
        ///CertPath.</summary>
        public X509CertificateCollection Certs
        {
            get {
                if (m_certs != null) {
                    return m_certs;
                } else if (m_certPath == "") {
                    return null;
                } else {
                    X509CertificateCollection c = new X509CertificateCollection();
                    c.Add(new X509Certificate2(m_certPath, m_certPass));
                    return c;
                }
            }
            set {
                m_certs = value;
            }
        }

        private string m_serverName;

        ///<summary>Retrieve or set the expected DNS name or IP address of the server.
        ///The value is also used for SNI when it contains a DNS name.</summary>
        public string ServerName
        {
            get { return m_serverName; }
            set { m_serverName = value; }
        }

        private string m_trustStorePath = "";

        ///<summary>Retrieve or set the path to a PEM or DER file containing trusted CA certificates.
        ///This is required for default server certificate validation.</summary>
        public string TrustStorePath
        {
            get { return m_trustStorePath; }
            set { m_trustStorePath = value; }
        }

        private SslPolicyErrors m_acceptablePolicyErrors = SslPolicyErrors.None;

        ///<summary>Retrieve or set the set of ssl policy errors that
        ///are deemed acceptable</summary>
        public SslPolicyErrors AcceptablePolicyErrors
        {
            get { return m_acceptablePolicyErrors; }
            set { m_acceptablePolicyErrors = value; }
        }

        /// <summary>
        /// An optional client specified SSL certificate validation callback.  If this is not specified,
        /// the default callback will be used in conjunction with the AcceptablePolicyErrors property to 
        /// determine if the remote server certificate is valid.
        /// </summary>
        public RemoteCertificateValidationCallback CertificateValidationCallback { get; set; }

        /// <summary>
        /// Legacy callback retained for source compatibility. Bouncy Castle TLS does not support it;
        /// use CertPath and CertPassphrase to select a client PKCS#12 credential.
        /// </summary>
        public LocalCertificateSelectionCallback CertificateSelectionCallback { get; set; }

        ///<summary>Construct an SslOption specifying both the server cannonical name
        ///and the client's certificate path.
        ///</summary>
        public SslOption(string serverName, string certPath, bool enabled)
        {
            m_serverName= serverName;
            m_certPath = certPath;
            m_enabled = enabled;
            CertificateValidationCallback = null;
            CertificateSelectionCallback  = null;
        }

        ///<summary>Construct an SslOption with just the server cannonical name.
        ///The Certificate path is set to an empty string
        ///</summary>
        public SslOption(string serverName): this(serverName, "", false)
        {
        }

        ///<summary>Construct an SslOption with no parameters set</summary>
        public SslOption(): this("", "", false)
        {
        }

    }
}
