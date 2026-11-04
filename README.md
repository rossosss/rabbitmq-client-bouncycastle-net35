# RabbitMQ.Client with Bouncy Castle TLS for .NET 3.5

This repository contains a fork of RabbitMQ.Client 3.4.3 that replaces the
system TLS transport with Bouncy Castle 1.8.10. Its primary target is .NET
Framework 3.5 on Windows XP, where Schannel does not provide the required TLS
1.2 capabilities.

**Current status: alpha (`3.4.3-alpha.1`).** The client and smoke test build,
and automated certificate, SNI, and credential-selection tests are included.
Real RabbitMQ, long-running, and target-OS validation must still be performed
before a production release. Do not use this alpha in production without your
own compatibility and security review.

## Package contents

The `RabbitMQ.Client.BouncyCastle.Net35` package contains:

- RabbitMQ.Client 3.4.3, targeting .NET Framework 3.5;
- the unmodified Bouncy Castle 1.8.10 CLR 2.0 assembly;
- XML documentation and PDB files;
- license and third-party notices.

Bouncy Castle is bundled because the old `BouncyCastle` NuGet package does not
provide version 1.8.10. The resulting package has no external NuGet dependency
and can be installed from a local directory without internet access.

The alpha assemblies are not strong-named. Package identity and signing policy
may be reviewed before a stable release. `AssemblyVersion` remains `3.4.3.0`;
the informational and NuGet package version is `3.4.3-alpha.1`.

## TLS configuration

A PEM or DER trust store containing the expected CA certificate is required.
The Windows system certificate store is not used by the Bouncy Castle
transport.

```csharp
ConnectionFactory factory = new ConnectionFactory();
factory.HostName = "rabbit.example.com";
factory.Port = 5671;
factory.UserName = "test";
factory.Password = "secret";

factory.Ssl.Enabled = true;
factory.Ssl.ServerName = "rabbit.example.com";
factory.Ssl.TrustStorePath = @"C:\certificates\rabbit-ca.cer";

using (IConnection connection = factory.CreateConnection())
using (IModel channel = connection.CreateModel())
{
    channel.QueueDeclare("test", false, false, false, null);
    channel.BasicPublish("", "test", null,
        System.Text.Encoding.UTF8.GetBytes("hello"));
}
```

For client certificate authentication, provide a PKCS#12 file containing the
private key and certificate chain:

```csharp
factory.Ssl.CertPath = @"C:\certificates\client.p12";
factory.Ssl.CertPassphrase = "client-password";
```

Client credentials are filtered using the server's requested certificate types,
signature algorithms, and certificate authorities. RSA, DSA, and ECDSA key types
are recognized; the TLS transport itself is limited to TLS 1.2.

International DNS names are converted to their ASCII Punycode representation
for both SNI and certificate hostname validation. IP addresses are validated
against IP subject alternative names and are not sent in SNI.

## Security behavior and limitations

- The certificate chain, validity period, server authentication usage, and DNS
  or IP name are checked before a connection is accepted.
- Certificate revocation checking is disabled: CRL and OCSP are not used.
- Only TLS 1.2 is supported. `SslOption.Version` is retained for source
  compatibility but does not select another protocol version. TLS 1.3 is not
  provided by Bouncy Castle 1.8.10.
- The default Bouncy Castle 1.8.10 cipher-suite list is used. It has not been
  restricted to a project-specific security policy.
- `CertificateSelectionCallback` and programmatic `SslOption.Certs` credentials
  are not supported; use `CertPath` with PKCS#12.
- `CertificateValidationCallback` receives `null` for its `X509Chain` argument.
- `AcceptablePolicyErrors` and a permissive validation callback can disable
  important security checks. Do not enable them merely to bypass a certificate
  error.
- Protect the trust-store and PKCS#12 files from unauthorized modification and
  keep the system clock synchronized.

A .NET 4.8 application can normally consume the .NET 3.5 assembly. This is
useful for testing the same managed TLS transport on Windows Server 2008 R2,
where system cipher suites are limited by Schannel. A separate, verified
`net48` target is not part of this alpha.

## Build and package

Prerequisites:

- .NET Framework 3.5 reference assemblies;
- classic .NET Framework MSBuild;
- NuGet CLI (`nuget.exe`) for packaging.

From the repository root, in a Developer Command Prompt:

```bat
msbuild src\rabbitmq-dotnet-client\RabbitMQDotNetClient.sln /t:Rebuild /p:Configuration=Release /m
msbuild tests\RabbitMQ.Client.SmokeTest\RabbitMQ.Client.SmokeTest.csproj /t:Rebuild /p:Configuration=Release /m
nuget.exe pack RabbitMQ.Client.BouncyCastle.Net35.nuspec -Properties "version=3.4.3-alpha.1" -OutputDirectory release
```

The old solution is most reliably built with the .NET Framework 4 MSBuild, for
example `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe`.

Install the resulting local package in NuGet Package Manager:

```powershell
Install-Package RabbitMQ.Client.BouncyCastle.Net35 -Version 3.4.3-alpha.1 -Source C:\path\to\release
```

## Tests

The self-contained Bouncy Castle TLS tests generate temporary certificates and
PKCS#12 files. They do not require RabbitMQ or OpenSSL:

```bat
cd src\rabbitmq-dotnet-client\projects\client\Unit
..\..\..\lib\nunit\nunit-console.exe /run=RabbitMQ.Client.Unit.TestBouncyCastleTls build\bin\unit-tests.dll
```

The inherited `TestSsl` integration fixture requires a configured RabbitMQ
broker and `SSL_CERTS_DIR`. Without that variable, its tests are explicitly
reported as ignored rather than passed.

The console smoke test can check either a TLS handshake or a complete AMQP
publish/consume round trip:

```bat
RabbitMQ.Client.SmokeTest.exe --host rabbit.example.com --port 5671 --tls --server-name rabbit.example.com --ca ca.pem --handshake-only
RabbitMQ.Client.SmokeTest.exe --host rabbit.example.com --tls --server-name rabbit.example.com --ca ca.pem --user test --password secret
```

Add `--client-cert client.p12 --client-cert-password secret` for client
authentication. Avoid passing real production passwords on a shared command
line.

## License and provenance

RabbitMQ.Client originates from the upstream `rabbitmq_v3_4_3` sources and is
dual-licensed under Apache-2.0 and MPL-1.1. This distribution uses the Apache
License 2.0; original notices are preserved.

Bouncy Castle 1.8.10 is an unmodified official CLR 2.0 binary distributed under
the Bouncy Castle License (MIT). See `LICENSE`, `THIRD-PARTY-NOTICES.txt`, and
the license files included in the package.
