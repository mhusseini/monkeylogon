using System;
using System.Linq;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace MonkeyLogon.Extensions
{
    public static class DataProtectionProviderExtensions
    {
        public const string StateQuerystringKey = "_state_";
        private const string ProtectorName = nameof(DataProtectionProviderExtensions);

        public static string ProtectQueryString(this IDataProtectionProvider dataProtectionProvider, IQueryCollection query)
        {
            var l = string.Join("&", query.Keys.Select(k => $"{HttpUtility.UrlEncode(k)}={HttpUtility.UrlEncode(query[k])}"));
            var protector = dataProtectionProvider.CreateProtector(ProtectorName);
            var @protected = Convert.ToBase64String(protector.Protect(Encoding.UTF8.GetBytes(l)));
            return @protected;
        }

        public static QueryString ReconstructQuerystring(this IDataProtectionProvider dataProtectionProvider, IQueryCollection originalQuery)
        {
            var @protected = originalQuery[StateQuerystringKey].FirstOrDefault();
            if (@protected == null)
            {
                return QueryString.Empty;
            }

            var protector = dataProtectionProvider.CreateProtector(ProtectorName);
            var originalQueryString = originalQuery.Keys.Where(k => k != StateQuerystringKey);
            var queryString = string.Join("&", originalQueryString.Select(k => $"{HttpUtility.UrlEncode(k)}={HttpUtility.UrlEncode(originalQuery[k])}"));
            var state = Encoding.UTF8.GetString(protector.Unprotect(Convert.FromBase64String(@protected)));
            var newQueryString = new QueryString($"?{queryString}&{state}");

            return newQueryString;
        }
    }
}