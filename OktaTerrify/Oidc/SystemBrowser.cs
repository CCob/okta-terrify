using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Browser;

namespace OktaTerrify.Oidc {
    internal class SystemBrowser : IBrowser {

        LoopbackHttpListener listener;

        public SystemBrowser(LoopbackHttpListener listener) { 
            this.listener = listener;
        }

        public async Task<BrowserResult> InvokeAsync(BrowserOptions options, CancellationToken cancellationToken = default) {

            var psi = new ProcessStartInfo();
            psi.UseShellExecute = true;
            psi.FileName = options.StartUrl;
                                            
            Process.Start(psi);

            try {
                var result = await listener.WaitForCallbackAsync();
                if (string.IsNullOrWhiteSpace(result)) {
                    return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = "Empty response." };
                }

                return new BrowserResult { Response = result, ResultType = BrowserResultType.Success };
            } catch (TaskCanceledException ex) {
                return new BrowserResult { ResultType = BrowserResultType.Timeout, Error = ex.Message };
            } catch (Exception ex) {
                return new BrowserResult { ResultType = BrowserResultType.UnknownError, Error = ex.Message };
            }           
        }
    }
}
