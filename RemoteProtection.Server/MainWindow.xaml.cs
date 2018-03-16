using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace RemoteProtection.Server
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        Thread server;
        Socket handler;
        Socket handlerTestConnection;
        Socket handlerForSend;
        Socket listenSocket;
        IPEndPoint answer;
        Socket listenSocketForSend;
        Socket listenSocketTestConnection;
        Thread serverTestConnection;
        List<string[]> reports = new List<string[]>();
        static IPAddress serverIp;
        static bool serverWorking = false;
        public MainWindow()
        {
            InitializeComponent();
            ReportsListView.MouseDoubleClick += new MouseButtonEventHandler(ReportsListView_MouseDoubleClick);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            if (listenSocket != null)
            {
                listenSocket.Dispose();
                listenSocket.Close();
            }

            if (listenSocketTestConnection != null)
            {
                listenSocketTestConnection.Close();
            }

            if (server != null)
            {
                try
                {
                    server.Abort();
                }
                catch (Exception) { }
            }

            Close();
        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            if (serverWorking == false) {
                ServerStatus.Fill = new SolidColorBrush(Colors.LawnGreen);
                serverWorking = true;
                btn_Run.Content = "Stop listen";
                TextBox_ServerIP.IsReadOnly = true;
                serverIp = IPAddress.Parse(TextBox_ServerIP.Text);
                server = new Thread(Server);
                server.IsBackground = true;
                server.Start();

                serverTestConnection = new Thread(ServerTestConnectionPoint);
                serverTestConnection.IsBackground = true;
                serverTestConnection.Start();
            }
            else
            {
                ServerStatus.Fill = new SolidColorBrush(Colors.Red);
                listenSocketTestConnection.Close();
                listenSocket.Close();
                server.Abort();
                btn_Run.Content = "Start listen";
                serverWorking = false;
                TextBox_ServerIP.IsReadOnly = false;
            }
        }

        private void ServerTestConnectionPoint()
        {
            while (serverWorking) {
                IPEndPoint ipPoint = new IPEndPoint(serverIp, 8666);

                // создаем сокет
                listenSocketTestConnection = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                // связываем сокет с локальной точкой, по которой будем принимать данные
                listenSocketTestConnection.Bind(ipPoint);

                // начинаем прослушивание
                listenSocketTestConnection.Listen(10);

                try
                {
                    handlerTestConnection = listenSocketTestConnection.Accept();
                }
                catch (Exception) { }

                StringBuilder builder = new StringBuilder();
                int bytes = 0; // количество полученных байтов
                byte[] data = new byte[256];

                do
                {
                    try
                    {
                        bytes = handlerTestConnection.Receive(data);
                    }
                    catch (Exception)
                    {
                        break;
                    }
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (handlerTestConnection.Available > 0);

                listenSocketTestConnection.Close();
            }
        }

        private void Server()
        {
            MessageBox.Show("Сервер запущен. Ожидание подключений...", "Warning",
                   MessageBoxButton.OK, MessageBoxImage.Information);

            while (true)
            {
                IPEndPoint ipPoint = new IPEndPoint(serverIp, 8005);

                // создаем сокет
                listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                // связываем сокет с локальной точкой, по которой будем принимать данные
                listenSocket.Bind(ipPoint);

                // начинаем прослушивание
                listenSocket.Listen(10);

                try
                {
                    handler = listenSocket.Accept();
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
                        bytes = handler.Receive(data);
                    }
                    catch (Exception)
                    {

                    }
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (handler.Available > 0);

                var parse = builder.ToString().Split('|');

                reports.Add(parse);

                if (parse.Length > 3)
                {
                    ReportsListView.Dispatcher.Invoke(DispatcherPriority.Background, new
                            Action(() =>
                            {
                                ReportsListView.Items.Add($"User name: {parse[2]}; App name: {parse[1]}");
                            }));
                }

                handler.Shutdown(SocketShutdown.Both);
                handler.Close();

                listenSocket.Close();
            }
        }

        private void ReportsListView_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            var dr = MessageBox.Show("Имя пользователя: " + reports[ReportsListView.SelectedIndex][2] + ";" + Environment.NewLine + "Имя приложения: " + reports[ReportsListView.SelectedIndex][1] + Environment.NewLine + "Информация о перехваченном пакете: " + Environment.NewLine + reports[ReportsListView.SelectedIndex][3] + Environment.NewLine + "Yes - блокировка. No - игнорирование. Cancel - отмена.", "Packet report",
                    MessageBoxButton.YesNoCancel, MessageBoxImage.Information);
            string message = String.Empty;

            if (dr == MessageBoxResult.Yes)
            {
                message = reports[ReportsListView.SelectedIndex][0] + "|1|" + reports[ReportsListView.SelectedIndex][1];

                ReportsListView.Items.Remove(ReportsListView.SelectedItems[0]);
                ReportsListView.Items.Refresh();
            }
            else if (dr == MessageBoxResult.No)
            {
                message = reports[ReportsListView.SelectedIndex][0] + "|0|" + reports[ReportsListView.SelectedIndex][1];

                ReportsListView.Items.Remove(ReportsListView.SelectedItems[0]);
                ReportsListView.Items.Refresh();
            }
            else
            {
                return;
            }       

            //server.Abort();
            answer = new IPEndPoint(serverIp, 8010);
            listenSocketForSend = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listenSocketForSend.Connect(answer);

            byte[] data = new byte[256];
            data = Encoding.Unicode.GetBytes(message);

            listenSocketForSend.Send(data);
            MessageBox.Show("Ответ отправлен.", "Warning",
                MessageBoxButton.OK, MessageBoxImage.Information);

            listenSocketForSend.Shutdown(SocketShutdown.Both);
            listenSocketForSend.Close();
        }
    }
}
