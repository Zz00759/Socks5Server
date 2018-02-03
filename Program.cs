using System;
using System.Collections.Generic;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;
using System.Collections;
using Kingthy.Test.Socks5.Server.Core;

namespace Kingthy.Test.Socks5.Server
{
    class Program
    {
        static string Username = "test";//用户名
        static string Password = "test";//密码
        static public bool IsRun = false;//是否运行
        static bool IsNeedAuth = false;//是否需要验证
        static Socket ProxySocket;
        static int ListenPort = 1080;
        static ArrayList ClientSocks = new ArrayList();
        static int SockNum = 0;
        static object obj = new object();
        static void BeginProxy()
        {
            IsRun = true;
            IPAddress ip = IPAddress.Any;
            ProxySocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            ProxySocket.Bind(new IPEndPoint(ip, ListenPort));
            ProxySocket.Listen(100);
            Console.WriteLine("Bind On 0.0.0.0:" + ListenPort.ToString());
            while (IsRun)
            {
                try
                {
                    Socket clientSocket = ProxySocket.Accept();
                    Console.WriteLine(" 接受了来自 " + ((IPEndPoint)clientSocket.RemoteEndPoint).Address.ToString() + ":" + ((IPEndPoint)clientSocket.RemoteEndPoint).Port.ToString() + "的连接");
                    ClientSocks.Add(clientSocket);
                    Thread T = new Thread(ProcessClient);
                    T.Start(clientSocket);
                }
                catch
                {
                    break;
                }
            }

        }
        static void StartTransData(Socket clisock, Socket sersock)
        {
            int SocketNum;
            byte[] RecvBuf = new byte[1024 * 4];
            lock (obj)
            {
                SocketNum = ++SockNum;
            }
            int Len;


            String DstHost = ((IPEndPoint)sersock.RemoteEndPoint).Address.ToString() + ":";
            DstHost += ((IPEndPoint)sersock.RemoteEndPoint).Port.ToString();
            String SrcHost = ((IPEndPoint)sersock.LocalEndPoint).Address.ToString() + ":";
            SrcHost += ((IPEndPoint)sersock.LocalEndPoint).Port.ToString();
            while (IsRun)
            {

                try
                {
                    if (clisock.Poll(1000, SelectMode.SelectRead))
                    {

                        Len = clisock.Receive(RecvBuf);



                        if (Len == 0)
                        {
                            clisock.Shutdown(SocketShutdown.Both);
                            clisock.Close();
                            sersock.Shutdown(SocketShutdown.Both);
                            sersock.Close();
                            break;
                        }
                        else
                        {
                            Len = sersock.Send(RecvBuf, 0, Len, 0);
                            Console.WriteLine("【" + SockNum.ToString() + "】" + SrcHost + "==>" + DstHost + "[发送" + Len.ToString() + "字节]");


                        }

                    }
                    if (sersock.Poll(1000, SelectMode.SelectRead))
                    {

                        Len = sersock.Receive(RecvBuf);


                        if (Len == 0)
                        {
                            sersock.Shutdown(SocketShutdown.Both);
                            sersock.Close();
                            clisock.Shutdown(SocketShutdown.Both);
                            clisock.Close();
                            break;
                        }
                        else
                        {
                            Len = clisock.Send(RecvBuf, 0, Len, 0);
                            Console.WriteLine("【" + SockNum.ToString() + "】" + DstHost + " ==> " + SrcHost + " [接收" + Len.ToString() + "字节]");


                        }



                    }
                }
                catch
                {

                    break;


                }
            }


        }
        static void ProcessClient(object sock)
        {
            byte[] RecvBuf = new byte[1024];
            Socket CliSock = (Socket)sock;
            Socket ServerSock;
            IPAddress ip = null;
            int Port = 0;
            byte[] buf = new byte[1024];
            int Len = 0;
            try
            {
                Len = CliSock.Receive(buf);

                byte SockVer = buf[0];

                if (IsNeedAuth)
                {
                    CliSock.Send(new byte[] { 0x05, 0x02 });  //需要验证
                    Len = CliSock.Receive(buf);
                    byte UserLen = buf[1];
                    byte[] User = new byte[UserLen];
                    Buffer.BlockCopy(buf, 2, User, 0, UserLen);



                    byte PassLen = buf[2 + UserLen];
                    byte[] Pass = new byte[PassLen];

                    Buffer.BlockCopy(buf, 3 + PassLen, Pass, 0, PassLen);
                    if (Encoding.ASCII.GetString(User) == Username && Encoding.ASCII.GetString(Pass) == Password)
                    {
                        CliSock.Send(new byte[] { 0x05, 0x00 });
                    }
                    else
                    {
                        CliSock.Send(new byte[] { 0x05, 0xff });
                        CliSock.Close();
                    }
                }
                else
                {
                    CliSock.Send(new byte[] { 0x05, 0x00 });
                }
            }
            catch
            {

            }
            try
            {
                Len = CliSock.Receive(RecvBuf);
                byte CMD = RecvBuf[1];
                byte ATYP = RecvBuf[3];
                if (CMD == 0x01)
                {
                    if (ATYP == 0x01)
                    {
                        if (RecvBuf.ToString().Split('.').Length == 5)
                        {
                            byte AddrLen = RecvBuf[4];
                            byte[] Addr = new byte[AddrLen];
                            Buffer.BlockCopy(RecvBuf, 5, Addr, 0, AddrLen);
                            IPAddress[] ips = Dns.GetHostAddresses(Addr.ToString());
                            ip = ips[0];
                            Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];
                        }
                        else
                        {
                            byte[] Addr = new byte[4];
                            Buffer.BlockCopy(RecvBuf, 4, Addr, 0, 4);
                            String sip = "";
                            foreach (byte b in Addr)
                            {
                                sip += b.ToString() + ".";
                            }
                            IPAddress[] ips = Dns.GetHostAddresses(sip.Remove(sip.Length - 1));
                            ip = ips[0];
                            Port = 256 * RecvBuf[9] + RecvBuf[10];
                        }
                    }
                    else if (ATYP == 0x03)
                    {
                        byte AddrLen = RecvBuf[4];
                        byte[] Addr = new byte[AddrLen];
                        Buffer.BlockCopy(RecvBuf, 5, Addr, 0, AddrLen);

                        String HostName = System.Text.Encoding.Default.GetString(Addr);
                        IPAddress[] ips = Dns.GetHostAddresses(HostName);
                        ip = ips[0];
                        Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];
                    }

                    else
                    {

                        return;
                    }

                    CliSock.Send(new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
                }
            }
            catch
            {
                return;
            }

            try
            {
                ServerSock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                ServerSock.Connect(ip, Port);

                StartTransData(CliSock, ServerSock);
            }
            catch
            {
                CliSock.Shutdown(SocketShutdown.Both);
                CliSock.Close();
                return;
            }


        }

        static void Main(string[] args)
        {
            BeginProxy();
        }
    }
}
