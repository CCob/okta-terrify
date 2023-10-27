using System;
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OktaTerrify {
    internal static class ThreadedConsoleReader {

        static ConcurrentQueue<string> lines = new ConcurrentQueue<string>();        
        static AutoResetEvent lineRead = new AutoResetEvent(false);
        static volatile bool waiting = false;

        public static void Clear() {
            while (lines.TryDequeue(out _));
        }

        public static string WaitForLine(string banner) {

            string result;
            if(banner != null) {
                Console.WriteLine(banner);
            }

            waiting = true;
            while (!lines.TryDequeue(out result) && string.IsNullOrWhiteSpace(result)) {
                lineRead.WaitOne();
            }
            waiting = false;
            
            return result;          
        }

        public static Task ConsoleLoop() {
            
            ConsoleKeyInfo lastKey = default;
            StringBuilder sb = new StringBuilder();
            var trimChars = new char[] { ' ', '\r', '\n' };

            return Task.Run(() => {
                while (lastKey.Key != ConsoleKey.Escape) {
                    lastKey = Console.ReadKey(true);

                    if ((lastKey.Modifiers & ConsoleModifiers.Alt) == ConsoleModifiers.Alt)
                        continue;
                    if ((lastKey.Modifiers & ConsoleModifiers.Control) == ConsoleModifiers.Control)
                        continue;

                    if (waiting) {
                        if (lastKey.Key != ConsoleKey.Enter) {
                            sb.Append(lastKey.KeyChar);
                            Console.Write(lastKey.KeyChar);
                        } else {
                            Console.WriteLine();
                            lines.Enqueue(sb.ToString().Trim(trimChars));
                            sb.Clear();
                            lineRead.Set();
                        }
                    }
                }

                lineRead.Set();
            });   
        } 
    }
}
