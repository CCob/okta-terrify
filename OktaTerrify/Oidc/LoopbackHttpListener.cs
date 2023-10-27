using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;
using NLog;

namespace OktaTerrify.Oidc {
    public class LoopbackHttpListener  {

        ILogger log = LogManager.GetCurrentClassLogger();
        private HttpListener listener;
        const int DefaultTimeout = 60 * 5; // 5 mins (in seconds)
        TaskCompletionSource<string> source = new TaskCompletionSource<string>();
        Func<string, Task<bool>> challengeCallback;
        Dictionary<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>> handlers;
        int[] ports;

        public LoopbackHttpListener(int[] ports, Func<string, Task<bool>> challengeCallback ) {
            handlers = new Dictionary<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>> {
                {new Regex("/login/callback\\?"), new Func<HttpListenerRequest, HttpListenerResponse, Task>(HandleCallback) },
                {new Regex("/probe"), new Func<HttpListenerRequest, HttpListenerResponse, Task>(OkEmpty) },
                {new Regex("/challenge"), new Func<HttpListenerRequest, HttpListenerResponse, Task>(HandleChallenge) }        
            };
            this.challengeCallback = challengeCallback;
            this.ports = ports;
        }
        
        public void Start() {
            listener = new HttpListener();            
            foreach(var port in ports) { listener.Prefixes.Add("http://127.0.0.1:" + port.ToString() + "/"); }            
            listener.Start();            
            log.Info($"HTTP server listening on loopback ports {ports.Aggregate("", (current, str) => $"{str} {current}")}");
            Receive();  
            
        }
        public void Stop() {
            listener.Stop();
        }
        public Task<string> WaitForCallbackAsync(int timeoutInSeconds = DefaultTimeout) {
            Task.Run(async () => {
                await Task.Delay(timeoutInSeconds * 1000);
                source.TrySetCanceled();
            });

            return source.Task;
        }

#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
        async Task HandleCallback(HttpListenerRequest request, HttpListenerResponse response) {

            source.TrySetResult(ConstructQueryString(request.QueryString));
            try {
                response.StatusCode = 200;
                response.ContentType = "text/html";
            } catch (Exception) {
                response.StatusCode = 400;
                response.ContentType = "text/html";
            }
        }

        async Task OkEmpty(HttpListenerRequest request, HttpListenerResponse response) {
            response.StatusCode = 200;
        }

        async Task NotFound(HttpListenerRequest request, HttpListenerResponse response) {
            response.StatusCode = 404;
        }
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously


        async Task HandleChallenge(HttpListenerRequest request, HttpListenerResponse response) {
            var reader = new StreamReader(request.InputStream, Encoding.UTF8);
            var challenge = await reader.ReadToEndAsync();
            dynamic challengeObj = JsonConvert.DeserializeObject(challenge);
            if (await challengeCallback((string)challengeObj.challengeRequest)) {
                response.StatusCode = 200;
            } else {
                response.StatusCode = 405;
            }
        }

        void Receive() {
            listener.BeginGetContext(new AsyncCallback(ListenerCallback), listener);
        }

        async void ListenerCallback(IAsyncResult result) {
            if (listener.IsListening) {

                var context = listener.EndGetContext(result);
                var request = context.Request;
                var response = context.Response;

                response.AppendHeader("Access-Control-Allow-Origin", "*");
                response.AppendHeader("Access-Control-Allow-Methods", "*");
                response.AppendHeader("Access-Control-Allow-Headers", "content-type,x-okta-xsrftoken");

                // do something with the request
                log.Debug($"{request.HttpMethod} {request.Url.PathAndQuery}");
                response.ContentLength64 = 0;

                if (request.HttpMethod == "OPTIONS" && handlers.Any(kvp => kvp.Key.Match(request.Url.PathAndQuery).Success)) {
                    response.StatusCode = 204;
                } else {

                    var handler = handlers.Where(kvp => kvp.Key.Match(request.Url.PathAndQuery).Success).FirstOrDefault();

                    if (handler.Equals(default(KeyValuePair<Regex, Func<HttpListenerRequest, HttpListenerResponse, Task>>))) {
                        await NotFound(request, response);
                    } else {
                        await handler.Value(request, response);
                    }
                }

                response.Close();
                Receive();
               
            }
        }

        static string ConstructQueryString(NameValueCollection parameters) {
            List<string> items = new List<string>();

            foreach (string name in parameters)
                items.Add(string.Concat(name, "=", System.Web.HttpUtility.UrlEncode(parameters[name])));

            return string.Join("&", items.ToArray());
        }
    }
}
