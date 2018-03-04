using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.RegularExpressions;

namespace RemoteProtection.Client
{
    class NetStatPortsAndProcessNames
    {
        static int lastPid;
        public static Process p = new Process();


        public static List<ProcessWithNetwork> GetNetStatPorts()
        {
            var Ports = new List<ProcessWithNetwork>();

            try
            {
                ProcessStartInfo ps = new ProcessStartInfo();
                ps.Arguments = "-a -n -o";
                ps.FileName = "netstat.exe";
                ps.UseShellExecute = false;
                ps.WindowStyle = ProcessWindowStyle.Hidden;
                ps.RedirectStandardInput = true;
                ps.RedirectStandardOutput = true;
                ps.RedirectStandardError = true;

                p.StartInfo = ps;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.UseShellExecute = false;
                p.Start();

                StreamReader stdOutput = p.StandardOutput;
                StreamReader stdError = p.StandardError;

                string content = stdOutput.ReadToEnd() + stdError.ReadToEnd();
                string exitStatus = p.ExitCode.ToString();

                if (exitStatus != "0")
                {
                    // Command Errored. Handle Here If Need Be
                }

                //Get The Rows
                string[] rows = Regex.Split(content, "\r\n");
                foreach (string row in rows)
                {
                    //Split it baby
                    string[] tokens = Regex.Split(row, "\\s+");
                    if (tokens.Length > 4 && (tokens[1].Equals("UDP") || tokens[1].Equals("TCP")))
                    {
                        string localAddress = Regex.Replace(tokens[2], @"\[(.*?)\]", "1.1.1.1");
                        Ports.Add(new ProcessWithNetwork
                        {
                            protocol = localAddress.Contains("1.1.1.1") ? String.Format("{0}v6", tokens[1]) : String.Format("{0}v4", tokens[1]),
                            port_number = localAddress.Split(':')[1],
                            process_name = tokens[1] == "UDP" ? LookupProcess(Convert.ToInt16(tokens[4])) : LookupProcess(Convert.ToInt16(tokens[5])),
                            PID = lastPid.ToString()
                        });
                    }
                }

            }
            catch (Exception)
            {
                //Console.WriteLine(ex.Message);
            }
            return Ports;
        }

        public static string LookupProcess(int pid)
        {
            lastPid = pid;
            string procName;
            try { procName = Process.GetProcessById(pid).ProcessName; }
            catch (Exception) { procName = "-"; }
            return procName;
        }
    }

    public class ProcessWithNetwork
    {
        public string name
        {
            get
            {
                return string.Format("{0} ({1} port {2})", this.process_name, this.protocol, this.port_number);
            }
            set { }
        }
        public string port_number { get; set; }
        public string process_name { get; set; }
        public string protocol { get; set; }
        public string PID { get; set; }
    }
}