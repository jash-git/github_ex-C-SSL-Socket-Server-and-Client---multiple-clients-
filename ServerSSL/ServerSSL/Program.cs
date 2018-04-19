using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServerSSL
{
    class server
    {
        // Server IP and Port
        public static string HostIP = "127.0.0.1";

        // Port
        public static int Port = 888;

        // SSL Certyficate connect
        X509Certificate serverCertificate = new X509Certificate2("ssl.pfx", "password12345");

        // Reset client
        ManualResetEvent tcpClientConnected = new ManualResetEvent(false);

        // Read data from file or from mysql database
        static string ReadMessageDB(string msg)
        {
            string pos = "";
            msg = msg.Trim();
            msg = msg.Replace("<END>", "");
            try
            {
                // if you need JSON
                // dynamic userMsg = JsonConvert.DeserializeObject<dynamic>(msg);

                if (msg.Substring(0, 3) == "GET")
                {
                    pos = "[GET FROM SERVER]";
                }
                if (msg.Substring(0, 3) == "SET")
                {
                    pos = "[SET FROM SERVER]";
                }
                Console.WriteLine(" Command from client " + msg + "\r\n");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return "[ERROR]";
            }

            return pos;
        }

        // Read message from client
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the client. The client signals the end of the message using the "<END>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                // Read the client's test message.
                bytes = sslStream.Read(buffer, 0, buffer.Length);
                // Use Decoder class to convert from bytes to UTF8 in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for <END> or an empty message. 
                if (messageData.ToString().IndexOf("<END>") != -1)
                {
                    break;
                }
            } while (bytes != 0);
            //Console.WriteLine("FROM READMESSAGE " + messageData);

            return ReadMessageDB(messageData.ToString());
            //return messageData.ToString();
        }


        void ProcessIncomingData(object obj)
        {
            SslStream sslStream = (SslStream)obj;
            try
            {
                //
                // Set timeouts for the read and write to 5 seconds.
                sslStream.ReadTimeout = 1000;
                sslStream.WriteTimeout = 1000;
                // Read a message from the client.   
                Console.WriteLine("Waiting for client message...");
                string messageData = ReadMessage(sslStream);
                Console.WriteLine("Waiting for client message..." + messageData);
                // Write a message to the client.                 
                byte[] message = Encoding.UTF8.GetBytes(messageData + "<END>");
                sslStream.Write(message);
                sslStream.Flush();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        void ProcessIncomingConnection(IAsyncResult ar)
        {
            TcpListener listener = (TcpListener)ar.AsyncState;
            TcpClient client = listener.EndAcceptTcpClient(ar);
            SslStream sslStream = new SslStream(client.GetStream(), false);
            //Console.WriteLine("SOCKET TYPE " + client.Connected);

            try
            {
                sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls, true);
                sslStream.ReadTimeout = 1000;
                sslStream.WriteTimeout = 1000;

                // Show certs info
                DisplayCertificateInformation(sslStream);

                // remote ip address
                //Console.Write(((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString());
                IPEndPoint newclient = (IPEndPoint)client.Client.RemoteEndPoint;
                Console.WriteLine("Connected with {0} at port {1} and Serialize {2} HASH### {3}", newclient.Address, newclient.Port, newclient.Serialize().ToString(), newclient.GetHashCode());
            }
            catch (Exception ee)
            {
                Console.WriteLine("Client without sslSocket " + ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString());
                sslStream.Close();
                client.Client.Close();
            }
            ThreadPool.QueueUserWorkItem(ProcessIncomingData, sslStream);
            tcpClientConnected.Set();
        }

        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
            Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
            Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
            Console.WriteLine("Protocol: {0}", stream.SslProtocol);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Local certificate is null.");
            }
            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }

        public void start()
        {
            Thread t = new Thread(() =>
            {
                while (true)
                {
                    // Do something in second rhread
                    // UpdateBanIP();
                    Thread.Sleep(1000 * 60);
                }
            });
            t.Start();

            IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse(HostIP), Port);
            TcpListener listener = new TcpListener(endpoint);
            listener.Start();

            while (true)
            {
                tcpClientConnected.Reset();
                listener.BeginAcceptTcpClient(new AsyncCallback(ProcessIncomingConnection), listener);
                tcpClientConnected.WaitOne();
            }
        }

    }

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Multi user server. Recive save and send data to clients");
            //DateTime.Now.ToLongTimeString()
            Console.WriteLine(DateTime.Now + " Waiting for connections....");
            try
            {
                server s = new server();
                s.start();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                Console.ReadKey();
            }
        }
    }
}