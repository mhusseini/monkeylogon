using System.Threading.Tasks;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using MonkeyLogon.Extensions;

namespace MonkeyLogon
{
    public class RequestReconstructionMiddleWare
    {
        private readonly IDataProtectionProvider dataProtectionProvider;
        private readonly RequestDelegate next;

        public RequestReconstructionMiddleWare(RequestDelegate next, IDataProtectionProvider dataProtectionProvider)
        {
            this.next = next;
            this.dataProtectionProvider = dataProtectionProvider;
        }

        public Task Invoke(HttpContext httpContext)
        {
            var newQueryString = this.dataProtectionProvider.ReconstructQuerystring(httpContext.Request.Query);
            if (newQueryString != QueryString.Empty)
            {
                httpContext.Request.QueryString = newQueryString;
            }

            return this.next.Invoke(httpContext);
        }
    }
}