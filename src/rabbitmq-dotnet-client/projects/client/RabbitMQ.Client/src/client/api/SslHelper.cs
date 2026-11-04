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
//
// Modified to use Bouncy Castle for TLS transport and certificate validation.
//---------------------------------------------------------------------------

using System;
using System.IO;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using RabbitMQ.Client.Impl;

namespace RabbitMQ.Client
{
    ///<summary>Creates Bouncy Castle TLS streams for RabbitMQ connections.</summary>
    public class SslHelper
    {
        ///<summary>Upgrade a TCP stream to TLS using the supplied options.</summary>
        public static Stream TcpUpgrade(Stream tcpStream, SslOption sslOption)
        {
            return TcpUpgrade(tcpStream, sslOption, sslOption.ServerName);
        }

        ///<summary>Upgrade a TCP stream to TLS using the supplied options and host name.</summary>
        public static Stream TcpUpgrade(Stream tcpStream, SslOption sslOption, string hostName)
        {
            if (tcpStream == null)
            {
                throw new ArgumentNullException("tcpStream");
            }
            if (sslOption == null)
            {
                throw new ArgumentNullException("sslOption");
            }
            if (sslOption.CertificateSelectionCallback != null)
            {
                throw new NotSupportedException("CertificateSelectionCallback is not supported by Bouncy Castle TLS; use CertPath with a PKCS#12 file.");
            }

            string serverName = String.IsNullOrEmpty(sslOption.ServerName) ? hostName : sslOption.ServerName;
            if (String.IsNullOrEmpty(serverName))
            {
                throw new ArgumentException("SslOption.ServerName or a broker host name is required for TLS.", "sslOption");
            }

            BouncyCastleTlsClient client = new BouncyCastleTlsClient(sslOption, serverName);
            TlsClientProtocol protocol = new TlsClientProtocol(tcpStream, new SecureRandom());
            protocol.Connect(client);
            return protocol.Stream;
        }
    }
}
