using System;
using System.Text;
using RabbitMQ.Client;

namespace RabbitMQ.Client.SmokeTest
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (Array.Exists(args, delegate(string arg) { return arg == "--help" || arg == "-h"; }))
            {
                PrintUsage();
                return 0;
            }

            try
            {
                Options options = Options.Parse(args);
                Run(options);
                return 0;
            }
            catch (ArgumentException e)
            {
                Console.Error.WriteLine("ERROR: " + e.Message);
                PrintUsage();
                return 2;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("FAIL: " + e);
                return 1;
            }
        }

        private static void Run(Options options)
        {
            Console.WriteLine("RabbitMQ.Client " + typeof(ConnectionFactory).Assembly.GetName().Version);
            Console.WriteLine("Bouncy Castle " + typeof(Org.BouncyCastle.Crypto.Engines.AesEngine).Assembly.GetName().Version);

            ConnectionFactory factory = new ConnectionFactory();
            factory.HostName = options.HostName;
            factory.VirtualHost = options.VirtualHost;
            factory.UserName = options.UserName;
            factory.Password = options.Password;
            factory.RequestedHeartbeat = 10;

            if (options.Port != 0)
            {
                factory.Port = options.Port;
            }

            if (options.UseTls)
            {
                factory.Ssl.Enabled = true;
                factory.Ssl.ServerName = options.ServerName ?? options.HostName;
                factory.Ssl.TrustStorePath = options.TrustStorePath;
                factory.Ssl.CertPath = options.ClientCertPath ?? "";
                factory.Ssl.CertPassphrase = options.ClientCertPassword;
                if (options.Port == 0)
                {
                    factory.Port = 5671;
                }
            }

            Console.WriteLine("Connecting to " + options.HostName + ":" + factory.Port + " (TLS: " + options.UseTls + ")");

            if (options.HandshakeOnly)
            {
                RunTlsHandshake(options, factory);
                return;
            }

            using (IConnection connection = factory.CreateConnection())
            using (IModel channel = connection.CreateModel())
            {
                string queueName = channel.QueueDeclare("", false, true, true, null).QueueName;
                string payload = "RabbitMQ.Client smoke test " + DateTime.UtcNow.ToString("o");
                byte[] expectedBody = Encoding.UTF8.GetBytes(payload);

                channel.BasicPublish("", queueName, null, expectedBody);

                QueueingBasicConsumer consumer = new QueueingBasicConsumer(channel);
                channel.BasicConsume(queueName, true, consumer);

                RabbitMQ.Client.Events.BasicDeliverEventArgs delivery;
                if (!consumer.Queue.Dequeue(10000, out delivery))
                {
                    throw new TimeoutException("The published message was not received within 10 seconds.");
                }

                string actual = Encoding.UTF8.GetString(delivery.Body);
                if (actual != payload)
                {
                    throw new Exception("The received message does not match the published message.");
                }

                Console.WriteLine("PASS: published and received " + expectedBody.Length + " bytes on queue " + queueName);
            }
        }

        private static void RunTlsHandshake(Options options, ConnectionFactory factory)
        {
            using (System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient())
            {
                client.Connect(options.HostName, factory.Port);
                using (System.IO.Stream stream = SslHelper.TcpUpgrade(client.GetStream(), factory.Ssl, options.HostName))
                {
                    Console.WriteLine("PASS: TLS handshake and certificate validation succeeded");
                }
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("Usage: RabbitMQ.Client.SmokeTest.exe [options]");
            Console.WriteLine("  --host <name>                 Broker host (default: localhost)");
            Console.WriteLine("  --port <number>               Broker port (default: 5672, or 5671 with TLS)");
            Console.WriteLine("  --vhost <name>                Virtual host (default: /)");
            Console.WriteLine("  --user <name>                 User name (default: guest)");
            Console.WriteLine("  --password <value>            Password (default: guest)");
            Console.WriteLine("  --tls                         Enable TLS");
            Console.WriteLine("  --server-name <name>          TLS server name (default: broker host)");
            Console.WriteLine("  --ca <path>                   Trusted CA certificate in PEM or DER format");
            Console.WriteLine("  --client-cert <path>          Client certificate and private key in PKCS#12 format");
            Console.WriteLine("  --client-cert-password <value>  Client PKCS#12 password");
            Console.WriteLine("  --handshake-only             Stop after the TLS handshake (requires --tls)");
        }

        private sealed class Options
        {
            internal string HostName = "localhost";
            internal int Port;
            internal string VirtualHost = "/";
            internal string UserName = "guest";
            internal string Password = "guest";
            internal bool UseTls;
            internal string ServerName;
            internal string TrustStorePath;
            internal string ClientCertPath;
            internal string ClientCertPassword;
            internal bool HandshakeOnly;

            internal static Options Parse(string[] args)
            {
                Options options = new Options();

                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "--host":
                            options.HostName = ReadValue(args, ref i);
                            break;
                        case "--port":
                            int port;
                            if (!int.TryParse(ReadValue(args, ref i), out port) || port < 1 || port > 65535)
                            {
                                throw new ArgumentException("The port must be an integer between 1 and 65535.");
                            }
                            options.Port = port;
                            break;
                        case "--vhost":
                            options.VirtualHost = ReadValue(args, ref i);
                            break;
                        case "--user":
                            options.UserName = ReadValue(args, ref i);
                            break;
                        case "--password":
                            options.Password = ReadValue(args, ref i);
                            break;
                        case "--tls":
                            options.UseTls = true;
                            break;
                        case "--server-name":
                            options.ServerName = ReadValue(args, ref i);
                            break;
                        case "--ca":
                            options.TrustStorePath = ReadValue(args, ref i);
                            break;
                        case "--client-cert":
                            options.ClientCertPath = ReadValue(args, ref i);
                            break;
                        case "--client-cert-password":
                            options.ClientCertPassword = ReadValue(args, ref i);
                            break;
                        case "--handshake-only":
                            options.HandshakeOnly = true;
                            break;
                        default:
                            throw new ArgumentException("Unknown option: " + args[i]);
                    }
                }

                if (options.HandshakeOnly && !options.UseTls)
                {
                    throw new ArgumentException("--handshake-only requires --tls.");
                }

                return options;
            }

            private static string ReadValue(string[] args, ref int index)
            {
                if (index + 1 >= args.Length)
                {
                    throw new ArgumentException("Missing value for " + args[index]);
                }

                index++;
                return args[index];
            }
        }
    }
}
