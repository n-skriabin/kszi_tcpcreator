using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Lab_01
{
    public partial class Form1 : Form
    {
        private string bitText;
        private string tcpText;
        private string sourceText;

        bool _DataIsEmpty = false;

        private Socket MainSocket;
        private byte[] ByteData = new byte[4096];

        private byte[] DataNull = new byte[4096];

        const int PORT_NO = 5000;
        const string SERVER_IP = "127.0.0.1";

        private delegate void AddTreeNode(TreeNode node);

        public Form1()
        {
            InitializeComponent();

            InitDataNullArray();
            StartListen();
            textBox3.ScrollBars = ScrollBars.Both;
            textBox3.WordWrap = false;
        }

        public void InitDataNullArray()
        {
            for (int i = 0; i < DataNull.Length; i++)
            {
                DataNull[i] = 0x00;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            sourceText = textBox1.Text;

            bitText = ToBinaryString(Encoding.ASCII, sourceText);

            textBox2.Text = bitText;         

            Thread thread2 = new Thread(ServerSide);
            thread2.Start();

            Thread thread1 = new Thread(ClientSide);
            thread1.Start();
        }

        static string ToBinaryString(Encoding encoding, string text)
        {
            return string.Join("", encoding.GetBytes(text).Select(n => Convert.ToString(n, 2).PadLeft(8, '0')));
        }

        public void ClientSide()
        {
            string textToSend = bitText;

            //---create a TCPClient object at the IP and port no.---
            TcpClient client = new TcpClient(SERVER_IP, PORT_NO);
            NetworkStream nwStream = client.GetStream();
            byte[] bytesToSend = ASCIIEncoding.ASCII.GetBytes(textToSend);

            //---send the text---
            nwStream.Write(bytesToSend, 0, bytesToSend.Length);

            //---read back the text---
            byte[] bytesToRead = new byte[client.ReceiveBufferSize];
            int bytesRead = nwStream.Read(bytesToRead, 0, client.ReceiveBufferSize);
            client.Close();
        }

        public void ServerSide()
        {
            IPAddress localAdd = IPAddress.Parse(SERVER_IP);
            TcpListener listener = new TcpListener(localAdd, PORT_NO);
            listener.Start();

            //---incoming client connected---
            TcpClient client = listener.AcceptTcpClient();

            //---get the incoming data through a network stream---
            NetworkStream nwStream = client.GetStream();
            byte[] buffer = new byte[client.ReceiveBufferSize];

            //---read incoming stream---
            int bytesRead = nwStream.Read(buffer, 0, client.ReceiveBufferSize);

            //---convert the data received into a string---

            string dataReceived = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            //Console.WriteLine("Received : " + dataReceived);

            ////---write back the text to the client---
            //Console.WriteLine("Sending back : " + dataReceived);
            nwStream.Write(buffer, 0, bytesRead);
            client.Close();
            listener.Stop();
        }

        public void StartListen()
        {
            // For sniffing the socket to capture the packet it has to be a raw
            // socket, with the address family being of type internetwork
            // and protocol being IP.
            MainSocket = new Socket(AddressFamily.InterNetwork,
                                    SocketType.Raw, ProtocolType.IP);
            //Bind the socket to the selected IP address.
            MainSocket.Bind(new IPEndPoint(IPAddress.Parse
                            ("127.0.0.1"), 0));
            //Set the socket options.
            MainSocket.SetSocketOption(SocketOptionLevel.IP,
                                       SocketOptionName.HeaderIncluded, true);
            byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
            // Capture outgoing packets.
            byte[] byOut = new byte[4] { 1, 0, 0, 0 };
            // Socket.IOControl is analogous to the WSAIoctl method of Winsock 2.
            MainSocket.IOControl(IOControlCode.ReceiveAll, byTrue, byOut);
            // Start receiving the packets asynchronously.
            MainSocket.BeginReceive(ByteData, 0, ByteData.Length,
                                    SocketFlags.None,
                                    new AsyncCallback(OnReceive), null);
        }

        private void OnReceive(IAsyncResult asyncResult)
        {
            try
            {
                int nReceived = MainSocket.EndReceive(asyncResult);
                // Analyze the bytes received.
                ParseData(ByteData, nReceived);

                ByteData = new byte[4096];
                // Making another call to BeginReceive so that we continue to receive
                // the incoming packets.
                MainSocket.BeginReceive(ByteData, 0, ByteData.Length,
                                        SocketFlags.None,
                                        new AsyncCallback(OnReceive), null);
                
            }
            catch (ObjectDisposedException) { }
            catch (Exception exception)
            {
                MessageBox.Show(exception.Message, "Network Sniffer",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void ParseData(byte[] byteData, int nReceived)
        {
            TreeNode rootNode = new TreeNode();
            // Since all protocol packets are encapsulated in the IP datagram
            // so we start by parsing the IP header and see what protocol data
            // is being carried by it.
            IpHeader ipHeader = new IpHeader(byteData, nReceived);
            TreeNode ipNode = MakeIPTreeNode(ipHeader);
            //rootNode.Nodes.Add(ipNode);

            // Now according to the protocol being carried by the IP datagram we parse
            // the data field of the datagram.
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    TcpHeader tcpHeader = new TcpHeader(ipHeader.Data,
                                            ipHeader.MessageLength);
                    string result = string.Empty;
                    foreach (var item in ipHeader.Data)
                    {
                        if (item == 0x00)
                        {
                            break;
                        }

                        result += Convert.ToString(item, 2).PadLeft(8, '0');
                    }
                    var test = tcpHeader.ByTCPData;

                    this.Invoke(new MethodInvoker(delegate ()
                    {
                        textBox3.Text = result;
                        //MessageBox.Show(result, "TCP-Package", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }));

                    TreeNode tcpNode = MakeTCPTreeNode(tcpHeader);
                    rootNode.Nodes.Add(tcpNode);
                    // If the port is equal to 53 then the underlying protocol is DNS.
                    // Note: DNS can use either TCP or UDP hence checking is done twice.
                    if (tcpHeader.DestinationPort == "53" ||
                        tcpHeader.SourcePort == "53")
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.Data,
                                            (int)tcpHeader.MessageLength);
                        rootNode.Nodes.Add(dnsNode);
                    }
                    break;
                case Protocol.Unknown:
                    break;
            }

            AddTreeNode addTreeNode = new AddTreeNode(OnAddTreeNode);
            rootNode.Text = ipHeader.SourceAddress.ToString() + "-" +
            ipHeader.DestinationAddress.ToString();

            if (ipHeader.DestinationAddress.ToString() == ipHeader.SourceAddress.ToString() && !_DataIsEmpty)
            {
                treeView.Invoke(addTreeNode, new object[] { rootNode });
            }
            // Thread safe adding of the nodes.
        }

        private TreeNode MakeIPTreeNode(IpHeader ipHeader)
        {
            TreeNode ipNode = new TreeNode();
            ipNode.Text = "IP";
            ipNode.Nodes.Add("Ver: " + ipHeader.Version);
            ipNode.Nodes.Add("Header Length: " + ipHeader.HeaderLength);
            ipNode.Nodes.Add("Differentiated Services: " +
                            ipHeader.DifferentiatedServices);
            ipNode.Nodes.Add("Total Length: " + ipHeader.TotalLength);
            ipNode.Nodes.Add("Identification: " + ipHeader.Identification);
            ipNode.Nodes.Add("Flags: " + ipHeader.Flags);
            ipNode.Nodes.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipNode.Nodes.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipNode.Nodes.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipNode.Nodes.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipNode.Nodes.Add("Protocol: " + "Unknown");
                    break;
            }
            ipNode.Nodes.Add("Checksum: " + ipHeader.Checksum);
            ipNode.Nodes.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipNode.Nodes.Add("Destination: " + ipHeader.DestinationAddress.ToString());
            return ipNode;
        }

        private TreeNode MakeTCPTreeNode(TcpHeader tcpHeader)
        {
            TreeNode tcpNode = new TreeNode();
            tcpNode.Text = "TCP";
            tcpNode.Nodes.Add("Source Port: " + tcpHeader.SourcePort);
            tcpNode.Nodes.Add("Destination Port: " + tcpHeader.DestinationPort);
            tcpNode.Nodes.Add("Sequence Number: " + tcpHeader.SequenceNumber);
            if (tcpHeader.AcknowledgementNumber != "")
            {
                tcpNode.Nodes.Add("Acknowledgement Number: " +
                                tcpHeader.AcknowledgementNumber);
            }
            tcpNode.Nodes.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpNode.Nodes.Add("Flags: " + tcpHeader.Flags);
            tcpNode.Nodes.Add("Window Size: " + tcpHeader.WindowSize);
            tcpNode.Nodes.Add("Urgent pointer: " + tcpHeader.UrgentPointer);
            tcpNode.Nodes.Add("Checksum: " + tcpHeader.Checksum);
            if (tcpHeader.UrgentPointer != "")
            {
                tcpNode.Nodes.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);
            }
            if (tcpHeader.ByTCPData[0] != 0x00)
            {
                tcpNode.Nodes.Add("Data: " + Encoding.ASCII.GetString(tcpHeader.ByTCPData, 0, tcpHeader.ByTCPData.Length));
                _DataIsEmpty = false;
            }
            else
            {
                _DataIsEmpty = true;
            }
            
            return tcpNode;
        }

        private TreeNode MakeDNSTreeNode(byte[] byteData, int nLength)
        {
            DnsHeader dnsHeader = new DnsHeader(byteData, nLength);
            TreeNode dnsNode = new TreeNode();
            dnsNode.Text = "DNS";
            dnsNode.Nodes.Add("Identification: " + dnsHeader.Identification);
            dnsNode.Nodes.Add("Flags: " + dnsHeader.Flags);
            dnsNode.Nodes.Add("Questions: " + dnsHeader.TotalQuestions);
            dnsNode.Nodes.Add("Answer RRs: " + dnsHeader.TotalAnswerRRs);
            dnsNode.Nodes.Add("Authority RRs: " + dnsHeader.TotalAuthorityRRs);
            dnsNode.Nodes.Add("Additional RRs: " + dnsHeader.TotalAdditionalRRs);
            return dnsNode;
        }

        private void OnAddTreeNode(TreeNode node)
        {
            treeView.Nodes.Add(node);
        }
    }
}
