using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using System.Management;

namespace RemoteProtection.Client
{
    public partial class MainWindow : Window
    {
        List<ProcessWithNetwork> processes;
        Thread serverTest;
        bool programmRun = false;
        Socket answerHandler;
        Socket answerSocket;
        static int port = 8005; // порт через которое работает приложение
        public static bool sentPackage = false;
        static IPAddress serverIp;
        Dictionary<string, int> detectedProcesses = new Dictionary<string, int>();
        static List<string> pathsProcesses = new List<string>();
        public static string dataPacket;
        public static string detectedProcess;
        public static List<HashSet<string>> detectedPortsProcesses = new List<HashSet<string>>();
        static string portOfProces = String.Empty;
        static bool packageDetected = false;
        Thread monitoring;
        Thread sniffing;
        Thread answers;
        static HashSet<string> processPorts = new HashSet<string>();

        public static Guid deviceId;
        static int lastPID;
        float maxCpuValue = 60;
        bool detected = false;
        bool CPUUsage = false;
        static HashSet<string> buff = new HashSet<string>();
        static int portForBloc = 0;
        public static int detectedPortNumber;
        private delegate void foo();
        ICaptureDevice captureDevice;

        public MainWindow()
        {
            InitializeComponent();

            CaptureDeviceList deviceList = CaptureDeviceList.Instance;
            captureDevice = deviceList[0];

            deviceId = Guid.NewGuid();
            TextBox_ID.Text = deviceId.ToString();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            if (!programmRun)
            {
                serverIp = IPAddress.Parse(TextBox_IP.Text);
                Run_Button.Content = "Disconnect/Stop";
                TextBox_IP.IsReadOnly = true;
                programmRun = true;

                ConnectionStatus.Fill = new SolidColorBrush(Colors.Orange);

                monitoring = new Thread(Monitoring);
                monitoring.IsBackground = true;
                monitoring.Start();

                answers = new Thread(acceptingAnswers);
                answers.IsBackground = true;
                answers.Start();
            }
            else
            {
                ConnectionStatus.Fill = new SolidColorBrush(Colors.Red);

                if (monitoring != null)
                {
                    monitoring.Abort();
                }

                if (sniffing != null)
                {
                    sniffing.Abort();
                }

                if (answers != null)
                {
                    answers.Abort();
                }

                Run_Button.Content = "Connect/Start";
                TextBox_IP.IsReadOnly = false;
                programmRun = false;
            }
        }

        public void acceptingAnswers()
        {
            IPEndPoint ipAnswersPoint = new IPEndPoint(serverIp, 8010);
            while (true)
            {
                // создаем сокет
                answerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                // связываем сокет с локальной точкой, по которой будем принимать данные
                answerSocket.Bind(ipAnswersPoint);

                // начинаем прослушивание
                answerSocket.Listen(10);

                try
                {
                    answerHandler = answerSocket.Accept();
                }
                catch (Exception) { break; }

                // получаем сообщение
                StringBuilder builder = new StringBuilder();
                int bytes = 0; // количество полученных байтов
                byte[] data = new byte[256]; // буфер для получаемых данных

                do
                {
                    try
                    {
                        bytes = answerHandler.Receive(data);
                    }
                    catch (Exception)
                    {

                    }
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (answerHandler.Available > 0);

                var response = builder.ToString();
                var parse = response.Split('|');
                

                if (parse[0] == deviceId.ToString() && parse[1] == "1")
                {
                    string nameApp = String.Empty;

                    int i = 0;
                    foreach (var item in detectedProcesses.Keys)
                    {
                        if (item == parse[2])
                        {
                            nameApp = item;
                            break;
                        }
                        i++;
                    }

                    MessageBox.Show("На вашем компьютере была обнаружена подозрительная активность. Приложению " + nameApp + " был заблокирован доступ в интернет брандмауэром Windows. Пожалуйста, обратитесь к вашему администратору.", "Warning",
                        MessageBoxButton.OK, MessageBoxImage.Information);

                    //AddRuleForPorts(detectedPortsProcesses[i]); //блокируем порты
                    AddRuleForApp(pathsProcesses[i]);//запрещаем приложению доступ в сеть
                    KillTask(detectedProcesses[parse[2]]);//"убиваем" процесс
                }

                // закрываем сокет
                //answerSocket.Shutdown(SocketShutdown.Both);
                answerHandler.Close();
                answerSocket.Close();
            }
        }

        public void AddRuleForApp(string processPath)
        {
            var rule = $"netsh advfirewall firewall add rule name=\"RuleBlockRemoteProtection\" dir=out action=block program=\"{processPath}\" enable=yes";

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Windows\System32\cmd.exe",
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();

            using (StreamWriter pWriter = process.StandardInput)
            {
                if (pWriter.BaseStream.CanWrite)
                {
                    foreach (var line in rule.Split('\n'))
                        pWriter.WriteLine(line);
                }
            }
        }

        private void Monitoring()
        {
            serverTest = new Thread(ServerTestConnection);
            serverTest.IsBackground = true;
            serverTest.Start();
            //buff = new HashSet<string>();
            PerformanceCounter total_cpu = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            while (true)
            {
                Thread.Sleep(100);

                float t = total_cpu.NextValue();

                if (t > maxCpuValue)
                {
                    CPUUsage = true;
                }
                else
                {
                    CPUUsage = false;
                }


                if (CPUUsage)
                {
                    processes = NetStatPortsAndProcessNames.GetNetStatPorts();
                    foreach (var process in processes)
                    {
                        buff = new HashSet<string>();
                        PerformanceCounter cpuCounter = new PerformanceCounter("Process", "% Processor Time", process.process_name);

                        double cpu = cpuCounter.NextValue();
                        Thread.Sleep(100);
                        cpu = cpuCounter.NextValue();

                        t = total_cpu.NextValue();
                        var procentCPU = cpu / Environment.ProcessorCount;
                       
                        
                        //это условие детектит подозрительный процесс
                        if (procentCPU > maxCpuValue)
                        {
                            foreach (var proc in processes)
                            {
                                if (process.process_name == proc.process_name)
                                {
                                    detectedProcess = process.process_name;
                                    //processPorts.Add(proc.port_number);
                                    buff.Add(proc.port_number);
                                    Int32.TryParse(proc.PID, out lastPID);
                                    //detectedProcesses.Add(detectedProcess);
                                }
                            }

                            //detectedPortsProcesses.Add(processPorts);
                            detected = true;
                            break;
                        }
                    }
                    //здесь идет отправка сообщений на сервер

                    if (detected)
                    {
                        captureDevice.OnPacketArrival += new PacketArrivalEventHandler(Program_OnPacketArrival);

                        captureDevice.Open(DeviceMode.Promiscuous, 1000);

                        captureDevice.StartCapture();

                        bool packageNotDetected = false;

                        for (int i = 0; i <= 10; i++)
                        {
                            Thread.Sleep(50);
                            if (i >= 10 && !packageDetected)
                            {
                                packageNotDetected = false;
                            }
                            else
                            {
                                packageNotDetected = true;
                            }
                        }

                        if (packageNotDetected)
                        {
                            IPEndPoint ipPoint = new IPEndPoint(serverIp, port);

                            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                            // подключаемся к удаленному хосту
                            try
                            {
                                socket.Connect(ipPoint);
                            }
                            catch
                            {
                                MessageBox.Show("Сервер не был найден. Подключение не было произведено.", "Connection error",
                                    MessageBoxButton.OK, MessageBoxImage.Error);

                                TextBox_IP.Dispatcher.Invoke(DispatcherPriority.Background, new
                                    Action(() =>
                                    {
                                        TextBox_IP.IsReadOnly = false;
                                    }));

                                break;
                            }

                            //отправляемая информация на сервер
                            var flag = false;
                            foreach (var process in detectedProcesses)
                            {
                                if(process.Key == detectedProcess)
                                {
                                    flag = true;
                                }
                            }

                            if (!flag)
                            {                               
                                string message = deviceId.ToString() + "|" + detectedProcess + "|" + Environment.UserName + "|" + dataPacket;
                                byte[] data = Encoding.Unicode.GetBytes(message);
                                socket.Send(data);

                                socket.Shutdown(SocketShutdown.Both);
                                socket.Close();

                                detectedProcesses.Add(detectedProcess, lastPID);
                                detectedPortsProcesses.Add(buff);
                                int RootProcessId = Process.GetProcessesByName(detectedProcess)[0].Id;

                                var path = GetProcessPath(RootProcessId);
                                pathsProcesses.Add(path);
                                buff = new HashSet<string>();
                            }

                            detected = false;
                        }
                    }
                    detected = false;
                }
            }
        }

        public static string GetProcessPath(int processId)
        {
            string MethodResult = "";
            try
            {
                string Query = "SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + processId;

                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(Query))
                {
                    using (ManagementObjectCollection moc = mos.Get())
                    {
                        string ExecutablePath = (from mo in moc.Cast<ManagementObject>() select mo["ExecutablePath"]).First().ToString();

                        MethodResult = ExecutablePath;

                    }

                }

            }
            catch //(Exception ex)
            {
                //ex.HandleException();
            }
            return MethodResult;
        }

        void ServerTestConnection()
        {
            while (true) {
                Thread.Sleep(1000);
                IPEndPoint ipPointTest = new IPEndPoint(serverIp, 8666);

                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                // подключаемся к удаленному хосту
                try
                {
                    socket.Connect(ipPointTest);
                }
                catch
                {
                    programmRun = false;
                    MessageBox.Show("Сервер не был найден. Подключение не было произведено.", "Connection error",
                        MessageBoxButton.OK, MessageBoxImage.Error);

                    if (monitoring != null)
                    {
                        monitoring.Abort();
                    }

                    if (sniffing != null)
                    {
                        sniffing.Abort();
                    }

                    TextBox_IP.Dispatcher.Invoke(DispatcherPriority.Background, new
                        Action(() =>
                        {
                            TextBox_IP.IsReadOnly = false;
                        }));

                    Run_Button.Dispatcher.Invoke(DispatcherPriority.Background, new
                        Action(() =>
                        {
                            Run_Button.Content = "Connect/Start";
                        }));
                    ConnectionStatus.Dispatcher.Invoke(DispatcherPriority.Background, new
                        Action(() =>
                        {
                            ConnectionStatus.Fill = new SolidColorBrush(Colors.Red);
                        }));
                   
                    socket.Close();
                    break;
                }
                ConnectionStatus.Dispatcher.Invoke(DispatcherPriority.Background, new
                        Action(() =>
                        {
                            ConnectionStatus.Fill = new SolidColorBrush(Colors.LawnGreen);
                        }));

                socket.Close();
            }
        }

        static void Program_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            Packet packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            // получение только TCP пакета из всего фрейма
            var tcpPacket = TcpPacket.GetEncapsulated(packet);
            // получение только IP пакета из всего фрейма
            var ipPacket = IpPacket.GetEncapsulated(packet);
            if (tcpPacket != null && ipPacket != null)
            {
                // IP адрес получателя
                var dstIp = ipPacket.DestinationAddress.ToString();
                // порт отправителя
                var srcPort = tcpPacket.SourcePort.ToString();
                dataPacket = tcpPacket.ParentPacket.ToString();

                if (dataPacket != null)
                {
                    foreach (var port in buff) {
                        if (srcPort == port)
                        {
                            Int32.TryParse(portOfProces, out portForBloc);
                            packageDetected = true;
                        }
                    }
                }
            }
        }

        public void AddRuleForPorts(HashSet<string> ports)//int portDetected
        {
            foreach (var port in ports) {
                int portDetected;
                Int32.TryParse(port, out portDetected);
                string name = "Block-" + portDetected.ToString();

                string commands = "netsh advfirewall firewall add rule dir=in action=block protocol=tcp localport=" + portDetected.ToString() + " name=\"" + name + "\" ";
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = @"C:\Windows\System32\cmd.exe",
                        RedirectStandardInput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();

                using (StreamWriter pWriter = process.StandardInput)
                {
                    if (pWriter.BaseStream.CanWrite)
                    {
                        foreach (var line in commands.Split('\n'))
                            pWriter.WriteLine(line);
                    }
                }
            }
        }

        public void KillTask(int pid)
        {
            string commands = "taskkill /PID " + pid.ToString() + " /F";
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Windows\System32\cmd.exe",
                    RedirectStandardInput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();

            using (StreamWriter pWriter = process.StandardInput)
            {
                if (pWriter.BaseStream.CanWrite)
                {
                    foreach (var line in commands.Split('\n'))
                        pWriter.WriteLine(line);
                }
            }
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            if (monitoring != null)
            {
                monitoring.Abort();
            }

            if (sniffing != null)
            {
                sniffing.Abort();
            }

            Close();
        }
    }
}
